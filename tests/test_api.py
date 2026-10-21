"""The public API: keys, scopes, visibility, the assessment gate, quotas and the audit trail."""

import re
import uuid

from sqlalchemy import select

from app import jobs
from app.config import get_settings
from app.models import AccessLog, ApiKey, User
from app.security import hash_password
from tests.conftest import case_form_data, csrf_from, login

CLIENTS = str(__import__("pathlib").Path(__file__).resolve().parent.parent / "clients" / "python")


async def _key(client, csrf, scopes=("cases:read",), name="test job") -> str:
    r = await client.post(
        "/account/api-keys", data={"csrf_token": csrf, "name": name, "scopes": list(scopes), "days": "30"}
    )
    assert r.status_code == 200, r.text
    return re.search(r'value="(umk_[^"]+)"', r.text).group(1)


async def _case(client, csrf) -> uuid.UUID:
    r = await client.post("/cases", data=case_form_data(csrf, name=f"API {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    await jobs.wait_for_all()
    return uuid.UUID(r.headers["location"].rsplit("/", 1)[1])


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


async def test_keys_are_shown_once_and_stored_as_a_fingerprint(client, db):
    csrf = await login(client)
    token = await _key(client, csrf)
    key = await db.scalar(select(ApiKey).where(ApiKey.prefix == token.split("_")[1]))
    assert key.key_hash != token and token not in key.key_hash and key.scopes == ["cases:read"]
    assert token not in (await client.get("/account")).text  # never shown again
    me = await client.get("/api/v1/me", headers=_auth(token))
    assert me.status_code == 200 and me.json()["key"]["scopes"] == ["cases:read"]


async def test_no_key_bad_key_and_revoked_keys_are_refused(client, db):
    assert (await client.get("/api/v1/cases")).json() == {
        "error": "A valid API key is required (Authorization: Bearer umk_...)",
        "status": 401,
    }
    assert (await client.get("/api/v1/cases", headers=_auth("umk_nope_nope"))).status_code == 401
    csrf = await login(client)
    token = await _key(client, csrf)
    key = await db.scalar(select(ApiKey).where(ApiKey.prefix == token.split("_")[1]))
    r = await client.post(f"/account/api-keys/{key.id}/revoke", data={"csrf_token": csrf})
    assert r.status_code == 303
    assert (await client.get("/api/v1/cases", headers=_auth(token))).status_code == 401


async def test_scopes_visibility_and_the_assessment_gate(client, db):
    csrf = await login(client)
    case_id = await _case(client, csrf)
    reader = await _key(client, csrf, scopes=("cases:read",))
    cases = (await client.get("/api/v1/cases", headers=_auth(reader))).json()["cases"]
    assert any(c["id"] == str(case_id) for c in cases)
    detail = (await client.get(f"/api/v1/cases/{case_id}", headers=_auth(reader))).json()
    assert detail["targets"][0]["value"] == "janedoe" and detail["scans"][0]["status"] in ("completed", "partial")
    # Findings need their own permission...
    assert (await client.get(f"/api/v1/cases/{case_id}/findings", headers=_auth(reader))).status_code == 403
    full = await _key(client, csrf, scopes=("cases:read", "findings:read"))
    # ...and, like exports, a written assessment.
    gated = await client.get(f"/api/v1/cases/{case_id}/findings", headers=_auth(full))
    assert gated.status_code == 409 and "assessment" in gated.json()["error"]
    assessment = {"csrf_token": csrf, "analyst_assessment": "The handle janedoe on alpha is the subject."}
    await client.post(f"/cases/{case_id}/settings/assessment", data=assessment)
    body = (await client.get(f"/api/v1/cases/{case_id}/findings", headers=_auth(full))).json()
    assert body["format"] == "unmask-case-export" and body["findings"]
    graph = (await client.get(f"/api/v1/cases/{case_id}/graph", headers=_auth(full))).json()
    assert graph["edges"] and "evidence" in graph["edges"][0]
    zipped = await client.get(f"/api/v1/cases/{case_id}/bundle", headers=_auth(full))
    assert zipped.headers["content-type"] == "application/zip" and len(zipped.headers["x-manifest-sha256"]) == 64
    stix = await client.get(f"/api/v1/cases/{case_id}/stix", headers=_auth(full))
    assert stix.headers["content-type"].startswith("application/stix+json") and stix.json()["type"] == "bundle"
    logged = (
        await db.scalars(select(AccessLog).where(AccessLog.case_id == case_id, AccessLog.action == "api_export"))
    ).all()
    assert logged and logged[0].detail["api_key"] == full.split("_")[1]


async def test_a_key_sees_only_its_owners_cases(client, db):
    email = f"other-{uuid.uuid4().hex[:6]}@example.com"
    db.add(User(email=email, password_hash=hash_password("other-password-12")))
    await db.commit()
    csrf = await login(client)
    case_id = await _case(client, csrf)
    await client.post("/logout", data={"csrf_token": csrf})
    csrf2 = await login(client, email, "other-password-12")
    theirs = await _key(client, csrf2)
    assert (await client.get(f"/api/v1/cases/{case_id}", headers=_auth(theirs))).status_code == 404
    assert all(
        c["id"] != str(case_id) for c in (await client.get("/api/v1/cases", headers=_auth(theirs))).json()["cases"]
    )


async def test_scans_need_the_scope_and_count_against_the_quota(client, monkeypatch):
    csrf = await login(client)
    case_id = await _case(client, csrf)
    reader = await _key(client, csrf)
    assert (await client.post(f"/api/v1/cases/{case_id}/scans", headers=_auth(reader))).status_code == 403
    writer = await _key(client, csrf, scopes=("cases:read", "scans:write"))
    r = await client.post(f"/api/v1/cases/{case_id}/scans", headers=_auth(writer))
    assert r.status_code == 202 and r.json()["number"] == 2
    await jobs.wait_for_all()
    status = await client.get(f"/api/v1/cases/{case_id}/scans/2", headers=_auth(writer))
    assert status.json()["status"] in ("completed", "partial")
    monkeypatch.setattr(get_settings(), "max_scans_per_day", 0)
    assert (await client.post(f"/api/v1/cases/{case_id}/scans", headers=_auth(writer))).status_code == 429


async def test_the_schema_is_published(client):
    schema = (await client.get("/api/v1/openapi.json")).json()
    assert schema["info"]["title"] == "UNMASK API" and "/api/v1/cases/{case_id}/findings" in schema["paths"]


async def test_key_creation_is_validated(client):
    csrf = await login(client)
    r = await client.post("/account/api-keys", data={"csrf_token": csrf, "name": "x", "scopes": ["admin:everything"]})
    assert r.status_code == 422 and "at least one permission" in r.text
    assert csrf_from(r.text)


async def test_the_python_client_round_trips(client, app):
    """clients/python/unmask_client.py against the real app (its HTTP layer swapped for the test client)."""
    import asyncio
    import io
    import sys
    import urllib.error

    sys.path.insert(0, CLIENTS)
    from unmask_client import Unmask, UnmaskError

    csrf = await login(client)
    token = await _key(client, csrf)
    loop = asyncio.get_running_loop()

    class _Resp(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def opener(req, timeout=None):
        path = req.full_url.split("testserver", 1)[1]
        r = asyncio.run_coroutine_threadsafe(
            client.request(req.get_method(), path, headers=dict(req.headers)), loop
        ).result()
        if r.status_code >= 400:
            raise urllib.error.HTTPError(req.full_url, r.status_code, "error", {}, io.BytesIO(r.content))
        return _Resp(r.content)

    api = Unmask("http://testserver", token, opener=opener)
    me = await asyncio.to_thread(api.me)
    assert me["key"]["scopes"] == ["cases:read"]
    assert isinstance(await asyncio.to_thread(api.cases), list)
    try:
        await asyncio.to_thread(api.start_scan, str(uuid.uuid4()))
    except UnmaskError as exc:
        assert exc.status == 403 and "scans:write" in exc.message
