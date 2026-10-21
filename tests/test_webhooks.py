"""Signed webhooks and audit-log export."""

import json
import re
import time
import uuid

import httpx
import pytest
from sqlalchemy import delete, select

from app import jobs
from app.models import Webhook
from app.services import webhooks
from tests.conftest import case_form_data, csrf_from, login


@pytest.fixture
def receiver(monkeypatch):
    got = []
    status = {"code": 200}

    def handler(request):
        got.append(request)
        return httpx.Response(status["code"])

    monkeypatch.setattr(webhooks, "transport", httpx.MockTransport(handler))
    monkeypatch.setattr(webhooks, "RETRY_DELAYS", (0, 0))
    return got, status


async def _hook(client, csrf, url="https://hooks.example.org/unmask"):
    form = {"csrf_token": csrf, "url": url, "events": ["scan.finished", "watch.changes"]}
    r = await client.post("/integrations/webhooks/new", data=form)
    m = re.search(r'value="(whsec_[^"]+)"', r.text)
    return r, m.group(1) if m else None


def test_signatures_verify_and_expire():
    body = b'{"x":1}'
    now = int(time.time())
    sig = webhooks.sign("s3cret", now, body)
    assert webhooks.verify("s3cret", now, body, sig)
    assert not webhooks.verify("other", now, body, sig)
    assert not webhooks.verify("s3cret", now, body + b" ", sig)
    assert not webhooks.verify("s3cret", now - 3600, body, webhooks.sign("s3cret", now - 3600, body))


async def test_a_finished_scan_is_delivered_signed_and_without_case_data(client, db, receiver):
    got, _ = receiver
    await db.execute(delete(Webhook))
    await db.commit()
    csrf = await login(client)
    r, secret = await _hook(client, csrf)
    assert secret and "shown once" in r.text
    name = f"Webhook case {uuid.uuid4().hex[:6]}"
    await client.post("/cases", data=case_form_data(csrf, name=name, tools=["fake_ok"]))
    await jobs.wait_for_all()
    await webhooks.drain()
    assert got, "no delivery"
    req = got[-1]
    body = req.content
    assert webhooks.verify(secret, int(req.headers["x-unmask-timestamp"]), body, req.headers["x-unmask-signature"])
    payload = json.loads(body)
    assert payload["event"] == "scan.finished" and payload["data"]["new_findings"] >= 1
    text = body.decode()
    assert name not in text and "janedoe" not in text and "alpha.example" not in text
    hook = await db.scalar(select(Webhook))
    await db.refresh(hook)
    assert hook.last_status.startswith("delivered") and hook.secret == secret
    # Stored encrypted: neither the URL nor the secret appears in the row as written.
    from sqlalchemy import text as sql

    raw = (await db.execute(sql("SELECT url, secret FROM webhooks WHERE id = :i"), {"i": hook.id})).one()
    assert "hooks.example.org" not in raw.url and secret not in raw.secret


async def test_retries_on_server_errors_but_not_on_refusals(db, receiver):
    got, status = receiver
    hook = Webhook(url="https://hooks.example.org/x", secret="s", events=["scan.finished"])
    status["code"] = 503
    assert (await webhooks.deliver(hook, "scan.finished", {})).startswith("failed: HTTP 503") and len(got) == 3
    got.clear()
    status["code"] = 410
    await webhooks.deliver(hook, "scan.finished", {})
    assert len(got) == 1


async def test_webhooks_must_point_at_the_public_internet(client, receiver):
    csrf = await login(client)
    r, secret = await _hook(client, csrf, url="https://metadata.internal/hook")
    assert secret is None and "receive webhooks" in r.text


async def test_webhooks_and_audit_export_are_for_administrators(client, db):
    from app.models import User
    from app.security import hash_password

    email = f"analyst-{uuid.uuid4().hex[:6]}@example.com"
    db.add(User(email=email, password_hash=hash_password("analyst-password-1")))
    await db.commit()
    await login(client, email, "analyst-password-1")
    csrf = csrf_from((await client.get("/account")).text)
    r = await client.post("/integrations/webhooks/new", data={"csrf_token": csrf, "url": "https://x.example/h",
                                                              "events": ["scan.finished"]})  # fmt: skip
    assert r.status_code == 403
    assert (await client.get("/integrations/audit.csv")).status_code == 403
    r = await client.post("/account/api-keys", data={"csrf_token": csrf, "name": "siem", "scopes": ["audit:read"]})
    assert r.status_code == 422 and "Only administrators" in r.text


async def test_audit_export_is_neutralised_and_itself_audited(client, db):
    page = await client.get("/login")
    await client.post("/login", data={"email": "=HYPERLINK(1)@x.example", "password": "x",
                                      "csrf_token": csrf_from(page.text)})  # fmt: skip
    csrf = await login(client)
    r = await client.get("/integrations/audit.csv?days=1")
    assert r.status_code == 200 and r.text.startswith("﻿timestamp,action")
    assert "\n=" not in r.text and ",=" not in r.text
    lines = (await client.get("/integrations/audit.jsonl?days=1")).text.strip().splitlines()
    assert any(json.loads(line)["action"] == "audit_export" for line in lines)
    key = await client.post("/account/api-keys", data={"csrf_token": csrf, "name": "siem", "scopes": ["audit:read"]})
    token = re.search(r'value="(umk_[^"]+)"', key.text).group(1)
    api = (await client.get("/api/v1/audit", headers={"Authorization": f"Bearer {token}"})).json()
    assert api["entries"] and all("action" in e for e in api["entries"])


def test_audit_csv_cells_cannot_become_formulas():
    from app.services.auditlog import _cell, to_csv

    assert _cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and _cell("+1") == "'+1" and _cell("@x") == "'@x"
    assert _cell({"a": 1}) == '{"a": 1}' and _cell(None) == ""
    csv_text = to_csv([{"timestamp": "t", "action": "-cmd", "user": None, "case_id": None, "ip": "1", "detail": {}}])
    assert "'-cmd" in csv_text
