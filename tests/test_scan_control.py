"""Stopping scans, one active scan per case, and results that arrive mid-scan."""

import asyncio
import time
import uuid

import pytest
from sqlalchemy import select

from app import jobs
from app.adapters import registry
from app.adapters.base import EntityCandidate, RawResult, ToolAdapter, run_tool_subprocess
from app.models import Entity, ScanRun
from app.services.tools import sync_tool_config
from tests.conftest import case_form_data, login

release = asyncio.Event()


class FakeSlowAdapter(ToolAdapter):
    """Blocks until the test releases it, like a long Maigret run."""

    name = "fake_slow"
    label = "Fake Slow"
    input_types = ["username"]

    async def run(self, target_value, context_tags):
        await release.wait()
        return [RawResult(self.name, target_value, None)]

    def parse(self, raw):
        url = f"https://slow.example/{raw.target_value}"
        return [EntityCandidate(type="account", value=url, attributes={"site": "slow", "url": url})]


@pytest.fixture
async def slow_env(db):
    release.clear()
    registry.register(FakeSlowAdapter())
    await sync_tool_config(db)
    yield
    release.set()
    await jobs.wait_for_all()
    registry.unregister("fake_slow")


async def _start(client, csrf, tools) -> uuid.UUID:
    r = await client.post(
        "/cases", data=case_form_data(csrf, name=f"S {uuid.uuid4().hex[:6]}", target_value="janedoe", tools=tools)
    )
    return uuid.UUID(r.headers["location"].rsplit("/", 1)[1])


async def _latest_run(db, case_id) -> ScanRun:
    db.expire_all()
    return await db.scalar(select(ScanRun).where(ScanRun.case_id == case_id).order_by(ScanRun.run_number.desc()))


async def test_stopping_a_scan_keeps_earlier_results_and_discards_late_ones(client, db, slow_env):
    csrf = await login(client)
    case_id = await _start(client, csrf, ["fake_ok", "fake_slow"])
    for _ in range(50):  # fake_ok reports while fake_slow is still running
        run = await _latest_run(db, case_id)
        if run.jobs_done >= 1:
            break
        await asyncio.sleep(0.05)
    assert run.status == "running" and run.jobs_done == 1

    page = await client.get(f"/cases/{case_id}")
    assert 'data-active="1"' in page.text and "A scan is already running" in page.text

    # Another "Run scan" while one is active returns the same scan instead of a new one.
    again = await client.post(f"/cases/{case_id}/scans", headers={"HX-Request": "true", "X-CSRF-Token": csrf})
    assert f"Scan {run.run_number}" in again.text
    assert (await _latest_run(db, case_id)).id == run.id

    r = await client.post(
        f"/cases/{case_id}/scans/{run.id}/cancel", headers={"HX-Request": "true", "X-CSRF-Token": csrf}
    )
    assert r.status_code == 200 and "Stopped" in r.text and r.headers["HX-Trigger"] == "scan-finished"
    release.set()
    await jobs.wait_for_all()

    run = await _latest_run(db, case_id)
    assert run.status == "cancelled"
    assert "stopped by admin@example.com after 1 of 2" in run.failure_details["_cancelled"]
    sites = {e.attributes.get("site") for e in (await db.scalars(select(Entity).where(Entity.case_id == case_id)))}
    assert {"alpha", "beta"} <= sites and "slow" not in sites
    # With the scan stopped, a new one can start.
    new = await client.post(f"/cases/{case_id}/scans", headers={"HX-Request": "true", "X-CSRF-Token": csrf})
    assert f"Scan {run.run_number + 1}" in new.text


async def test_status_poll_announces_results_as_each_tool_reports(client, db, slow_env):
    csrf = await login(client)
    case_id = await _start(client, csrf, ["fake_ok", "fake_slow"])
    for _ in range(50):
        if (await _latest_run(db, case_id)).jobs_done >= 1:
            break
        await asyncio.sleep(0.05)
    fresh = await client.get(f"/cases/{case_id}/scan-status?was_running=1&seen=0", headers={"HX-Request": "true"})
    assert fresh.headers.get("HX-Trigger") == "results-updated"
    assert 'class="tool-state done"' in fresh.text and 'class="tool-state running"' in fresh.text
    same = await client.get(f"/cases/{case_id}/scan-status?was_running=1&seen=1", headers={"HX-Request": "true"})
    assert "HX-Trigger" not in same.headers
    # The finished tool's results are already scored, before the scan ends.
    alpha = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.type == "account"))
    assert "_score_explanation" in alpha.attributes


async def test_cancelling_kills_the_tool_process():
    task = asyncio.create_task(run_tool_subprocess(["sleep", "30"], timeout=60))
    await asyncio.sleep(0.3)
    started = time.monotonic()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert time.monotonic() - started < 5
