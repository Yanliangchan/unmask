"""Timeline diffs, watch mode, retention purges, scheduled health checks and alerts."""

import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import select, text, update

from app import alerts, jobs, scheduler
from app.adapters import registry
from app.adapters.base import AdapterError, EntityCandidate, RawResult
from app.config import get_settings
from app.models import AccessLog, Investigation, ScanRun, ToolConfig
from app.services.timeline import diff_runs
from tests.conftest import case_form_data, login


async def new_case(client, csrf, **overrides) -> uuid.UUID:
    data = case_form_data(csrf, **{"name": f"TL {uuid.uuid4().hex[:6]}", "tools": ["fake_ok"], **overrides})
    r = await client.post("/cases", data=data)
    assert r.status_code == 303, r.text
    await jobs.wait_for_all()
    return uuid.UUID(r.headers["location"].rsplit("/", 1)[1])


async def runs_of(db, case_id):
    db.expire_all()
    return list(
        (await db.scalars(select(ScanRun).where(ScanRun.case_id == case_id).order_by(ScanRun.run_number))).all()
    )


@pytest.fixture
def fake_ok(monkeypatch):
    adapter = registry.get_adapter("fake_ok")
    state = {"sites": ["alpha", "beta"], "bio": "v1", "fail": False}

    async def run(target_value, context_tags):
        if state["fail"]:
            raise AdapterError("upstream returned HTTP 503")
        return [RawResult("fake_ok", target_value, {"sites": list(state["sites"])})]

    def parse(raw):
        return [
            EntityCandidate(
                type="account", value=f"https://{s}.example/{raw.target_value}",
                attributes={"site": s, "bio": state["bio"] if s == "beta" else None},
                source_reliability="C", confidence=0.4,
                relation_type="has_account", relation_explanation=f"registered on {s}",
            )
            for s in raw.payload["sites"]
        ]  # fmt: skip

    monkeypatch.setattr(adapter, "run", run)
    monkeypatch.setattr(adapter, "parse", parse)
    return state


async def rescan(client, csrf, case_id):
    r = await client.post(f"/cases/{case_id}/scans", data={"csrf_token": csrf})
    assert r.status_code == 303
    await jobs.wait_for_all()


# --- Timeline -----------------------------------------------------------------------


async def test_timeline_diff_new_changed_gone_and_explained(fake_ok, client, db):
    csrf = await login(client)
    case_id = await new_case(client, csrf, target_value=f"tl{uuid.uuid4().hex[:6]}")
    fake_ok.update(sites=["beta", "gamma"], bio="v2")
    await rescan(client, csrf, case_id)

    r1, r2 = await runs_of(db, case_id)
    diff = await diff_runs(db, case_id, r1, r2)
    host = lambda items: sorted(i.entity.attributes["site"] for i in items)  # noqa: E731
    assert host(diff.new) == ["gamma"]
    assert host(diff.changed) == ["beta"]
    assert host(diff.gone) == ["alpha"] and diff.gone[0].real

    # Run 3: the tool fails. Nothing "disappeared" — the diff must say why.
    fake_ok["fail"] = True
    await rescan(client, csrf, case_id)
    r1, r2, r3 = await runs_of(db, case_id)
    diff = await diff_runs(db, case_id, r2, r3)
    assert diff.new == [] and host(diff.gone) == ["beta", "gamma"]
    assert all(not i.real and "fake_ok failed in run #3" in i.note for i in diff.gone)

    page = await client.get(f"/cases/{case_id}/tab/timeline")  # defaults to the latest two runs
    assert page.status_code == 200
    assert "not a real disappearance: fake_ok failed in run #3" in page.text
    page = await client.get(f"/cases/{case_id}/tab/timeline?a=1&b=2")
    assert "gamma.example" in page.text and "No longer found" in page.text


async def test_timeline_needs_two_runs(client, db):
    csrf = await login(client)
    case_id = await new_case(client, csrf)
    page = await client.get(f"/cases/{case_id}/tab/timeline")
    assert "Run another scan to compare" in page.text


# --- Watch mode ---------------------------------------------------------------------


def test_next_watch_run_is_jittered_within_bounds():
    now = datetime(2026, 1, 1, tzinfo=UTC)
    runs = {scheduler.next_watch_run("weekly", now) for _ in range(50)}
    assert len(runs) > 1  # never a synchronized schedule
    assert all(now + timedelta(days=7, hours=-12) <= r <= now + timedelta(days=7, hours=12) for r in runs)
    monthly = scheduler.next_watch_run("monthly", now)
    assert now + timedelta(days=29) < monthly < now + timedelta(days=31)


async def test_watch_toggle_schedules_and_tick_runs_due_scans(client, db, monkeypatch):
    csrf = await login(client)
    case_id = await new_case(client, csrf)
    r = await client.post(f"/cases/{case_id}/watch", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and "checked" in r.text and "weekly · next" in r.text

    db.expire_all()
    case = await db.get(Investigation, case_id)
    state = scheduler.watch_state(case)
    assert state["enabled"] and state["next_run_at"] > datetime.now(UTC) + timedelta(days=6)

    # Not due yet: nothing happens.
    await scheduler.tick()
    await jobs.wait_for_all()
    assert len(await runs_of(db, case_id)) == 1

    case = await db.get(Investigation, case_id)
    case.watch_config = {**case.watch_config, "next_run_at": (datetime.now(UTC) - timedelta(minutes=1)).isoformat()}
    await db.commit()
    result = await scheduler.tick()
    await jobs.wait_for_all()
    assert str(case_id) in result.watch_started
    runs = await runs_of(db, case_id)
    assert runs[-1].triggered_by == "watch_mode" and runs[-1].status == "completed"
    case = await db.get(Investigation, case_id)
    assert scheduler.watch_state(case)["next_run_at"] > datetime.now(UTC) + timedelta(days=6)
    actions = set((await db.scalars(select(AccessLog.action).where(AccessLog.case_id == case_id))).all())
    assert {"watch_on", "watch_scan"} <= actions


async def test_tick_starts_at_most_n_watch_scans(client, db, monkeypatch):
    monkeypatch.setattr(get_settings(), "watch_max_per_tick", 2)
    csrf = await login(client)
    ids = [await new_case(client, csrf) for _ in range(4)]
    past = (datetime.now(UTC) - timedelta(minutes=5)).isoformat()
    for cid in ids:
        case = await db.get(Investigation, cid)
        case.watch_config = {"enabled": True, "frequency": "weekly", "next_run_at": past}
    await db.commit()
    first = await scheduler.tick()
    await jobs.wait_for_all()
    assert len(first.watch_started) == 2
    second = await scheduler.tick()
    await jobs.wait_for_all()
    assert len(second.watch_started) == 2
    assert set(first.watch_started) | set(second.watch_started) == {str(i) for i in ids}


# --- Retention ----------------------------------------------------------------------


async def test_retention_purges_expired_cases_and_keeps_the_audit_trail(client, db):
    csrf = await login(client)
    expired, kept, active = [await new_case(client, csrf) for _ in range(3)]
    old = datetime.now(UTC) - timedelta(days=10)
    for cid in (expired, kept, active):
        await db.execute(
            update(Investigation)
            .where(Investigation.id == cid)
            .values(retention_days=5, created_at=old, updated_at=old)
        )
        await db.execute(update(ScanRun).where(ScanRun.case_id == cid).values(created_at=old))
    await db.execute(update(Investigation).where(Investigation.id == kept).values(permanently_active=True))
    await db.execute(update(Investigation).where(Investigation.id == active).values(retention_days=90))
    await db.commit()
    # Viewing a case must not extend its retention.
    await client.get(f"/cases/{expired}")
    await client.get(f"/cases/{expired}/entities")

    result = await scheduler.tick()
    assert result.purged == 1
    db.expire_all()
    assert await db.get(Investigation, expired) is None
    assert await db.get(Investigation, kept) is not None
    assert await db.get(Investigation, active) is not None
    # Every audit row about the purged case still says which case it was.
    rows = (
        (await db.execute(text("SELECT action FROM access_log WHERE detail->>'case_id' = :c"), {"c": str(expired)}))
        .scalars()
        .all()
    )
    assert "retention_purge" in rows and "create_case" in rows
    assert (await db.scalar(select(ScanRun.id).where(ScanRun.case_id == expired))) is None


async def test_dashboard_warns_before_purge(client, db):
    csrf = await login(client)
    cid = await new_case(client, csrf, name="Purge soon case")
    await db.execute(update(Investigation).where(Investigation.id == cid).values(retention_days=3))
    await db.commit()
    home = await client.get("/")
    assert "purged" in home.text and "purge-soon" in home.text


# --- Health checks and alerts ---------------------------------------------------------


async def test_tick_runs_due_health_checks_once(db):
    await db.execute(update(ToolConfig).where(ToolConfig.tool_name == "fake_ok").values(last_health_check_at=None))
    await db.commit()
    first = await scheduler.tick()
    assert "fake_ok" in first.health_checks
    db.expire_all()
    cfg = await db.get(ToolConfig, "fake_ok")
    assert cfg.last_health_ok is True
    second = await scheduler.tick()
    assert "fake_ok" not in second.health_checks


async def test_breaker_trip_sends_an_alert_without_case_data(client, db, monkeypatch):
    sent = []

    def handler(request):
        sent.append(request.content.decode())
        return httpx.Response(200)

    monkeypatch.setattr(get_settings(), "alert_webhook_url", "https://hooks.example/alert")
    monkeypatch.setattr(alerts, "transport", httpx.MockTransport(handler))
    await db.execute(
        update(ToolConfig)
        .where(ToolConfig.tool_name == "fake_fail")
        .values(enabled=True, circuit_open=False, consecutive_failures=2)
    )
    await db.commit()
    csrf = await login(client)
    await new_case(client, csrf, tools=["fake_fail"], target_value="secretuser")
    assert len(sent) == 1
    assert "fake_fail disabled after 3 consecutive failures" in sent[0]
    assert "secretuser" not in sent[0]
