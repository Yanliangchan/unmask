"""Misuse limits, ownership, sessions and the other safeguards added in the October 2026 audit."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from app import jobs
from app.config import get_settings
from app.models import AccessLog, Investigation, ScanRun, User
from app.security import hash_password, session_valid
from app.web import _safe_url
from tests.conftest import case_form_data, login


async def _case(client, csrf, **overrides) -> uuid.UUID:
    data = case_form_data(csrf, **{"name": f"S {uuid.uuid4().hex[:6]}", **overrides})
    r = await client.post("/cases", data=data)
    assert r.status_code == 303, r.text
    await jobs.wait_for_all()
    return uuid.UUID(r.headers["location"].rsplit("/", 1)[1])


async def _colleague(db) -> str:
    email = f"colleague-{uuid.uuid4().hex[:6]}@example.com"
    db.add(User(email=email, password_hash=hash_password("colleague-password-1")))
    await db.commit()
    return email


async def test_a_case_holds_a_bounded_number_of_targets(client):
    csrf = await login(client)
    limit = get_settings().max_targets_per_case
    paste = "\n".join(f"user{i:03d}" for i in range(limit + 1))
    r = await client.post("/cases", data=case_form_data(csrf, target_value="", paste=paste))
    assert r.status_code == 422 and f"at most {limit} targets" in r.text


async def test_short_authorization_notes_are_refused(client):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, authorization_note="ok"))
    assert r.status_code == 422 and "too short" in r.text


async def test_daily_target_quota_is_enforced_and_audited(client, db, monkeypatch):
    csrf = await login(client)
    await _case(client, csrf)
    monkeypatch.setattr(get_settings(), "max_targets_per_day", 1)
    r = await client.post("/cases", data=case_form_data(csrf, name="Over the limit"))
    assert r.status_code == 422 and "Daily limit reached" in r.text
    assert await db.scalar(select(AccessLog.id).where(AccessLog.action == "quota_exceeded").limit(1))


async def test_daily_scan_quota_is_enforced(client, monkeypatch):
    csrf = await login(client)
    case_id = await _case(client, csrf)
    monkeypatch.setattr(get_settings(), "max_scans_per_day", 0)
    r = await client.post(f"/cases/{case_id}/scans", data={"csrf_token": csrf})
    assert r.status_code == 429 and "Daily limit" in r.text


async def test_collaborators_cannot_widen_or_extend_a_case(client, db):
    email = await _colleague(db)
    csrf = await login(client)
    case_id = await _case(client, csrf)
    await client.post(f"/cases/{case_id}/settings/share", data={"csrf_token": csrf, "email": email})
    await client.post("/logout", data={"csrf_token": csrf})

    csrf2 = await login(client, email, "colleague-password-1")
    for path, data in [
        ("settings/retention", {"retention_days": "365", "permanently_active": "on"}),
        ("settings/watch", {"enabled": "on", "frequency": "weekly"}),
        ("settings/pivot", {"auto_pivot": "on"}),
        ("watch", {}),
        ("auto-pivot", {}),
    ]:
        r = await client.post(f"/cases/{case_id}/{path}", data={"csrf_token": csrf2, **data})
        assert r.status_code == 403, path
    db.expire_all()
    case = await db.get(Investigation, case_id)
    assert not case.permanently_active


async def test_signing_out_ends_every_session_of_the_account(app, db):
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with (
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as laptop,
        httpx.AsyncClient(transport=transport, base_url="http://testserver") as stolen,
    ):
        csrf = await login(laptop)
        stolen.cookies = laptop.cookies  # a copied cookie
        assert (await stolen.get("/")).status_code == 200
        await laptop.post("/logout", data={"csrf_token": csrf})
        assert (await stolen.get("/cases/new")).status_code == 303


def test_sessions_have_an_absolute_lifetime():
    user = User(email="x@example.com", password_hash="x", session_epoch=3)
    now = int(datetime.now(UTC).timestamp())
    assert session_valid({"epoch": 3, "iat": now - 60}, user)
    assert not session_valid({"epoch": 2, "iat": now - 60}, user)
    assert not session_valid({"epoch": 3, "iat": now - get_settings().session_absolute_seconds - 1}, user)
    assert not session_valid({"user_id": "legacy cookie without iat"}, user)


async def test_client_ip_comes_from_the_trusted_proxy_not_the_client(monkeypatch):
    from starlette.requests import Request

    from app.security import client_ip

    def req(xff):
        headers = [(b"x-forwarded-for", xff.encode())] if xff else []
        return Request({"type": "http", "headers": headers, "client": ("10.0.0.2", 1234)})

    assert client_ip(req("1.2.3.4")) == "10.0.0.2"  # no trusted proxies: the header is ignored
    monkeypatch.setattr(get_settings(), "trusted_proxy_hops", 1)
    assert client_ip(req("6.6.6.6, 203.0.113.7")) == "203.0.113.7"  # forged left entry ignored
    assert client_ip(req("")) == "10.0.0.2"


async def test_health_checks_are_for_administrators(client, db):
    email = await _colleague(db)
    await login(client, email, "colleague-password-1")
    home = await client.get("/")
    from tests.conftest import csrf_from

    r = await client.post("/tools/fake_ok/health-check", data={"csrf_token": csrf_from(home.text)})
    assert r.status_code == 403


async def test_data_exports_need_an_assessment(client):
    csrf = await login(client)
    case_id = await _case(client, csrf)
    for fmt in ("csv", "json", "stix"):
        r = await client.get(f"/cases/{case_id}/export.{fmt}")
        assert r.status_code == 303 and "error=assessment" in r.headers["location"]


def test_links_from_tool_output_are_web_links_only():
    assert _safe_url("https://github.com/x") == "https://github.com/x"
    assert _safe_url("mailto:a@b.example") == "mailto:a@b.example"
    assert _safe_url("javascript:alert(1)") == "#"
    assert _safe_url(" JaVaScRiPt:alert(1)") == "#"
    assert _safe_url("data:text/html,x") == "#"
    assert _safe_url(None) == "#"


async def test_the_scheduler_reaps_runs_a_dead_worker_left_behind(client, db):
    from app.services.scans import fail_interrupted_runs, stale_after

    csrf = await login(client)
    case_id = await _case(client, csrf)
    stale = datetime.now(UTC) - timedelta(seconds=get_settings().scan_job_timeout_seconds + 3600)
    run = ScanRun(case_id=case_id, run_number=99, status="running", created_at=stale, started_at=stale)
    db.add(run)
    await db.commit()
    # The scheduler tick runs exactly this first (scheduler.tick), every interval.
    assert await fail_interrupted_runs(db, older_than=stale_after()) >= 1
    await db.refresh(run)
    assert run.status == "failed"


async def test_a_run_that_cannot_be_queued_fails_instead_of_blocking_the_case(client, db, monkeypatch):
    from app import jobs as jobs_mod

    csrf = await login(client)
    case_id = await _case(client, csrf)

    def broken(*a, **kw):
        raise ConnectionError("redis down")

    monkeypatch.setattr(jobs_mod, "enqueue_scan", broken)
    await client.post(f"/cases/{case_id}/scans", data={"csrf_token": csrf})
    latest = await db.scalar(
        select(ScanRun).where(ScanRun.case_id == case_id).order_by(ScanRun.run_number.desc()).limit(1)
    )
    await db.refresh(latest)
    assert latest.status == "failed" and "could not queue" in latest.failure_details["_crashed"]
    await db.execute(update(ScanRun).where(ScanRun.case_id == case_id).values(status="completed"))
    await db.commit()


async def test_tools_page_reports_how_each_source_behaved(client, db):
    from app.services.sources import source_stats

    csrf = await login(client)
    case_id = await _case(client, csrf, tools=["fake_ok"])  # finds two accounts
    db.add(ScanRun(case_id=case_id, run_number=50, status="partial", tools_included=["fake_ok", "fake_fail"],
                   tools_completed=["fake_ok"], tools_failed=["fake_fail"],
                   failure_details={"fake_fail": "blocked by bot protection (HTTP 403)"}))  # fmt: skip
    await db.commit()
    stats = await source_stats(db, [case_id])
    assert stats["fake_ok"].runs == 2 and stats["fake_ok"].success_rate == 1.0 and stats["fake_ok"].findings == 2
    assert stats["fake_fail"].failed == 1 and stats["fake_fail"].blocked == 1 and stats["fake_fail"].success_rate == 0
    assert "HTTP 403" in stats["fake_fail"].last_failure
    page = (await client.get("/tools")).text
    assert "How each source has behaved" in page and "Fake Fail" in page
