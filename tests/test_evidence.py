"""Page snapshots (and the fetch guard), CSV/JSON/STIX exports, and expiring share links."""

import csv
import hashlib
import io
import json
import re
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, update

from app import crypto, jobs, safefetch
from app.models import Entity, ShareLink, Snapshot
from app.services.exports import STIX_NAMESPACE, TLP_AMBER
from tests.conftest import case_form_data, login

PAGE = b"<!doctype html><html><head><title>Jane Doe - Profile</title><script>alert(1)</script></head>" \
       b"<body><h1>Jane Doe</h1><p>Designer in London.</p></body></html>"  # fmt: skip


@pytest.fixture
def web(monkeypatch):
    """Public DNS for every host except *.internal, and a fake web."""
    monkeypatch.setattr(
        safefetch, "resolver", lambda host: ["10.0.0.5"] if host.endswith(".internal") else ["93.184.216.34"]
    )

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/moved":
            return httpx.Response(302, headers={"location": "http://metadata.internal/latest"})
        return httpx.Response(200, content=PAGE, headers={"content-type": "text/html; charset=utf-8"})

    safefetch.transport = httpx.MockTransport(handler)
    yield
    safefetch.transport = None


@pytest.mark.parametrize(
    "url",
    ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data", "file:///etc/passwd", "ftp://example.com/",
     "http://example.com:22/", "http://[::1]/", "http://db.internal/", "http://10.1.2.3/"],
)  # fmt: skip
async def test_fetch_guard_refuses_anything_not_public(url, web):
    with pytest.raises(safefetch.BlockedURL):
        await safefetch.fetch(url)


async def test_fetch_guard_checks_every_redirect(web):
    with pytest.raises(safefetch.BlockedURL):
        await safefetch.fetch("https://example.com/moved")
    page = await safefetch.fetch("https://example.com/ok")
    assert page.status_code == 200 and page.body == PAGE


async def _case(client, db, name="E"):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"{name} {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    return case_id, csrf


async def test_snapshot_keeps_exact_bytes_with_hash_and_shows_text_only(client, db, web):
    case_id, csrf = await _case(client, db)
    entity = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.type == "account").limit(1))
    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}
    r = await client.post(f"/cases/{case_id}/entities/{entity.id}/snapshot", headers=headers)
    digest = hashlib.sha256(PAGE).hexdigest()
    assert digest[:12] in json.loads(r.headers["HX-Trigger"])["toast"]["message"]
    snap = await db.scalar(select(Snapshot).where(Snapshot.entity_id == entity.id))
    assert snap.sha256 == digest and snap.title == "Jane Doe - Profile" and snap.size == len(PAGE)

    drawer = (await client.get(f"/cases/{case_id}/entities/{entity.id}/drawer")).text
    assert f"/snapshots/{snap.id}" in drawer and "Save page now" in drawer
    page = (await client.get(f"/cases/{case_id}/snapshots/{snap.id}")).text
    assert digest in page and "Matches" in page and "Designer in London." in page
    assert "alert(1)" not in page and "<h1>Jane Doe</h1>" not in page  # never rendered as HTML
    raw = await client.get(f"/cases/{case_id}/snapshots/{snap.id}/raw")
    assert raw.content == PAGE and raw.headers["content-security-policy"] == "sandbox"
    assert raw.headers["content-disposition"].startswith("attachment;")

    # A finding pointing inside the network is refused, not fetched.
    await db.execute(update(Entity).where(Entity.id == entity.id).values(
        attributes={**entity.attributes, "url": "http://169.254.169.254/latest"}))  # fmt: skip
    await db.commit()
    blocked = await client.post(f"/cases/{case_id}/entities/{entity.id}/snapshot", headers=headers)
    assert blocked.status_code == 400 and "public internet" in blocked.text


async def test_exports_csv_json_and_stix(client, db):
    case_id, csrf = await _case(client, db)
    samples = [("=HYPERLINK(\"http://evil\")", "name", False), ("jane@corp.example", "email", False),
               ("gone@corp.example", "email", True)]  # fmt: skip
    for value, kind, dismissed in samples:
        db.add(Entity(case_id=case_id, type=kind, value=value, value_digest=crypto.digest(kind, value), attributes={},
                      source_tool="analyst", confidence=0.6, dismissed_flag=dismissed))  # fmt: skip
    await db.commit()

    r = await client.get(f"/cases/{case_id}/export.csv")
    assert r.headers["content-disposition"].startswith("attachment;") and r.headers["content-type"].startswith(
        "text/csv"
    )
    rows = list(csv.DictReader(io.StringIO(r.text.lstrip("﻿"))))
    values = {row["value"] for row in rows}
    assert '\'=HYPERLINK("http://evil")' in values  # formula neutralised
    assert "jane@corp.example" in values and "gone@corp.example" not in values
    everything = (await client.get(f"/cases/{case_id}/export.csv?scope=all")).text
    assert "gone@corp.example" in everything and "ruled out" in everything

    data = (await client.get(f"/cases/{case_id}/export.json")).json()
    assert data["format"] == "unmask-case-export" and data["case"]["targets"][0]["value"] == "janedoe"
    assert {f["decision"] for f in data["findings"]} >= {"target", "undecided"}

    bundle = (await client.get(f"/cases/{case_id}/export.stix")).json()
    assert bundle["type"] == "bundle"
    grouping = next(o for o in bundle["objects"] if o["type"] == "grouping")
    assert grouping["object_marking_refs"] == [TLP_AMBER] and grouping["spec_version"] == "2.1"
    email = next(o for o in bundle["objects"] if o["type"] == "email-addr")
    expected = uuid.uuid5(STIX_NAMESPACE, json.dumps({"value": "jane@corp.example"}, separators=(",", ":")))
    assert email["id"] == f"email-addr--{expected}" and email["id"] in grouping["object_refs"]
    assert all(re.fullmatch(r"[a-z0-9-]+--[0-9a-f-]{36}", o["id"]) for o in bundle["objects"])
    assert not any(o.get("value") == "gone@corp.example" for o in bundle["objects"])
    assert (await client.get(f"/cases/{case_id}/export.xml")).status_code == 404


async def test_share_links_are_read_only_expiring_and_revocable(client, db, app):
    case_id, csrf = await _case(client, db, name="Share")
    r = await client.post(f"/cases/{case_id}/share-links", data={"csrf_token": csrf, "days": "7"})
    assert r.headers["location"].endswith("error=assessment")  # the report must carry a conclusion first
    assessment = "The handle janedoe on alpha is the subject; beta is unconfirmed."
    await client.post(
        f"/cases/{case_id}/settings/assessment", data={"csrf_token": csrf, "analyst_assessment": assessment}
    )

    page = (await client.post(f"/cases/{case_id}/share-links",
                              data={"csrf_token": csrf, "days": "90", "label": "Client"})).text  # fmt: skip
    url = re.search(r'value="(http://testserver/s/[^"]+)"', page).group(1)
    token = url.rsplit("/", 1)[1]
    link = await db.scalar(select(ShareLink).where(ShareLink.case_id == case_id))
    assert link.token_hash == hashlib.sha256(token.encode()).hexdigest() and token not in link.token_hash
    assert (link.expires_at - datetime.now(UTC)).days <= 30  # capped

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as anon:
        shared = await anon.get(f"/s/{token}")
        assert shared.status_code == 200 and "The handle janedoe on alpha is the subject" in shared.text
        assert "Shared read-only view" in shared.text and "Back to settings" not in shared.text
        assert shared.headers["x-robots-tag"].startswith("noindex") and shared.headers["cache-control"] == "no-store"
        assert (await anon.get(f"/cases/{case_id}")).status_code in (303, 401, 307)  # the case itself stays private
        assert (await anon.get("/s/not-a-real-token")).status_code == 404

        await client.post(f"/cases/{case_id}/share-links/{link.id}/revoke", data={"csrf_token": csrf})
        gone = await anon.get(f"/s/{token}")
        assert gone.status_code == 404 and "isn't available" in gone.text

        page = (await client.post(f"/cases/{case_id}/share-links", data={"csrf_token": csrf, "days": "1"})).text
        token2 = re.search(r'value="http://testserver/s/([^"]+)"', page).group(1)
        await db.execute(update(ShareLink).where(ShareLink.token_hash == hashlib.sha256(token2.encode()).hexdigest())
                         .values(expires_at=datetime.now(UTC) - timedelta(minutes=1)))  # fmt: skip
        await db.commit()
        assert (await anon.get(f"/s/{token2}")).status_code == 404
    link_id = link.id
    db.expire_all()
    link = await db.get(ShareLink, link_id)
    assert link.views == 1 and link.revoked_at is not None
