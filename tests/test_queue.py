"""RQ backend: priority queues, worker execution and the no-worker warning.

Needs TEST_REDIS_URL (a disposable Redis database) as well as TEST_DATABASE_URL.
"""

import asyncio
import os
import sys
import uuid

import pytest
from sqlalchemy import select

from app import jobs
from app.config import get_settings
from app.models import Investigation, ScanRun, User
from app.services.cases import TargetInput, create_case
from app.services.scans import create_scan_run
from tests.conftest import ROOT, TEST_REDIS, case_form_data, login

pytestmark = pytest.mark.skipif(not TEST_REDIS, reason="TEST_REDIS_URL not set")


@pytest.fixture
def rq_mode(monkeypatch):
    from redis import Redis

    settings = get_settings()
    monkeypatch.setattr(settings, "queue_backend", "rq")
    monkeypatch.setattr(settings, "redis_url", TEST_REDIS)
    monkeypatch.setattr(jobs, "_worker_cache", (0.0, None))
    conn = Redis.from_url(TEST_REDIS)
    conn.flushdb()
    yield conn
    conn.flushdb()


async def _work_burst(conn, **extra_env) -> None:
    env = {**os.environ, "UNMASK_QUEUE": "rq", "REDIS_URL": TEST_REDIS, **extra_env}
    proc = await asyncio.create_subprocess_exec(sys.executable, "-m", "tests.rq_burst", cwd=ROOT, env=env)
    assert await proc.wait() == 0


async def _case(db, name: str) -> Investigation:
    owner = await db.scalar(select(User).where(User.email == "admin@example.com"))
    case = await create_case(
        db,
        owner=owner,
        name=name,
        authorization_note="queue test",
        lawful_basis_confirmed=True,
        targets=[TargetInput(value=f"user{uuid.uuid4().hex[:6]}", type="username")],
        disabled_tools=["fake_fail"],
    )
    await db.commit()
    return case


async def test_manual_scans_preempt_watch_mode(rq_mode, db):
    watch_case, manual_case = await _case(db, "Watch case"), await _case(db, "Manual case")
    watch_run = await create_scan_run(db, watch_case, triggered_by="watch_mode")
    await db.commit()
    manual_run = await create_scan_run(db, manual_case, triggered_by="manual")
    await db.commit()
    # Watch-mode work was queued first, yet the manual scan must start first.
    jobs.enqueue_scan(watch_run.id, "watch_mode")
    jobs.enqueue_scan(manual_run.id, "manual")

    watch_id, manual_id = watch_run.id, manual_run.id

    await _work_burst(rq_mode)

    db.expire_all()
    watch_run, manual_run = await db.get(ScanRun, watch_id), await db.get(ScanRun, manual_id)
    assert watch_run.status == manual_run.status == "completed"
    assert manual_run.started_at < watch_run.started_at


async def test_http_scan_is_queued_not_run_inline(rq_mode, client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name="Queued case", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    run = await db.scalar(select(ScanRun).where(ScanRun.case_id == case_id))
    assert run.status == "queued"
    assert rq_mode.llen(f"rq:queue:{jobs.QUEUE_HIGH}") == 1

    # No worker is running: the UI must say so rather than spin forever.
    page = await client.get(f"/cases/{case_id}")
    assert "no scan worker is running" in page.text
    assert "No scan worker is running" in (await client.get("/")).text

    run_id = run.id
    await _work_burst(rq_mode)
    db.expire_all()
    run = await db.get(ScanRun, run_id)
    assert run.status == "completed" and run.tools_completed == ["fake_ok"]


async def test_worker_marks_crashed_scan_failed(rq_mode, db):
    case = await _case(db, "Crash case")
    run = await create_scan_run(db, case, triggered_by="manual")
    await db.commit()
    run_id = run.id
    jobs.enqueue_scan(run_id, "manual")
    await _work_burst(rq_mode, UNMASK_TEST_CRASH="1")
    db.expire_all()
    run = await db.get(ScanRun, run_id)
    assert run.status == "failed"
    assert "database went away" in run.failure_details["_crashed"]
