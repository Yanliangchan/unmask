"""Scans under load: coalesced rescoring, bounded jobs, platform faults kept off the tools' record."""

import asyncio
import uuid

from sqlalchemy import select
from sqlalchemy.exc import OperationalError

from app import jobs
from app.adapters import registry
from app.adapters.base import ToolAdapter
from app.config import get_settings
from app.models import ScanRun, ToolConfig
from app.services import scans
from app.services.tools import sync_tool_config
from tests.conftest import case_form_data, login


async def test_rescores_requested_while_one_runs_are_coalesced(monkeypatch):
    calls = []

    async def slow(session, case_id, semantic=True):
        calls.append(case_id)
        await asyncio.sleep(0.05)

    monkeypatch.setattr("app.correlation.engine.correlate_and_commit", slow)
    monkeypatch.setattr(scans, "QUICK_RESCORE_GAP", 0)
    case = uuid.uuid4()
    await asyncio.gather(*(scans._quick_rescore(case) for _ in range(12)))
    assert len(calls) == 2  # the first, and one more that picks up everything reported meanwhile
    assert case not in scans._rescoring


class _Slow(ToolAdapter):
    name = "fake_slow"
    label = "Fake Slow"
    input_types = ["username"]
    running = 0
    peak = 0

    async def run(self, target_value, context_tags):
        type(self).running += 1
        type(self).peak = max(type(self).peak, type(self).running)
        await asyncio.sleep(0.05)
        type(self).running -= 1
        return []

    def parse(self, raw):
        return []


class _DbDown(ToolAdapter):
    name = "fake_dbdown"
    label = "Fake DB down"
    input_types = ["username"]

    async def run(self, target_value, context_tags):
        raise OperationalError("SELECT 1", {}, Exception("connection pool exhausted"))

    def parse(self, raw):
        return []


async def test_jobs_per_scan_are_bounded_and_db_faults_dont_trip_the_breaker(client, db, monkeypatch):
    registry.register(_Slow())
    registry.register(_DbDown())
    try:
        await sync_tool_config(db)
        await db.commit()
        monkeypatch.setattr(get_settings(), "max_jobs_per_run", 2)
        csrf = await login(client)
        paste = "\n".join(f"handle{i}x" for i in range(6))
        form = case_form_data(csrf, name=f"Load {uuid.uuid4().hex[:6]}", target_value="", paste=paste,
                              tools=["fake_slow", "fake_dbdown"])  # fmt: skip
        r = await client.post("/cases", data=form)
        assert r.status_code == 303, r.text
        await jobs.wait_for_all()
        assert _Slow.peak <= 2
        case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
        run = await db.scalar(select(ScanRun).where(ScanRun.case_id == case_id))
        await db.refresh(run)
        assert "not the tool's fault" in run.failure_details["fake_dbdown"]
        cfg = await db.get(ToolConfig, "fake_dbdown")
        await db.refresh(cfg)
        assert cfg.consecutive_failures == 0 and not cfg.circuit_open
    finally:
        registry.unregister("fake_slow")
        registry.unregister("fake_dbdown")
