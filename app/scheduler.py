"""Periodic work: watch-mode scans, retention purges and tool health checks.

``tick()`` is idempotent and safe to run from several processes: with the RQ
backend a Redis lock lets only one run at a time. It runs every
``UNMASK_SCHEDULER_INTERVAL`` seconds inside the worker (RQ) or the web
process (inline).

Watch mode never fires as a burst: each case's next run gets random jitter,
and each tick starts at most ``UNMASK_WATCH_MAX_PER_TICK`` scans, picked at
random from those due.
"""

from __future__ import annotations

import asyncio
import logging
import random
import threading
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import dispose_engine, sessionmaker
from app.models import AccessLog, Investigation, ScanRun, ToolConfig

log = logging.getLogger(__name__)

FREQUENCY_DAYS = {"weekly": 7, "monthly": 30}
PURGE_WARNING_DAYS = 7
_rng = random.SystemRandom()


def next_watch_run(frequency: str, after: datetime) -> datetime:
    """``after`` + the interval ± up to 10% jitter (capped at 12 hours)."""
    days = FREQUENCY_DAYS.get(frequency, 7)
    jitter = min(days * 24 * 3600 * 0.1, 12 * 3600)
    return after + timedelta(days=days) + timedelta(seconds=_rng.uniform(-jitter, jitter))


def watch_state(case: Investigation) -> dict:
    cfg = case.watch_config or {}
    next_at = cfg.get("next_run_at")
    return {
        "enabled": bool(cfg.get("enabled")),
        "frequency": cfg.get("frequency", "weekly"),
        "next_run_at": datetime.fromisoformat(next_at) if next_at else None,
    }


def set_watch(case: Investigation, *, enabled: bool, frequency: str | None = None) -> None:
    cfg = dict(case.watch_config or {})
    frequency = frequency if frequency in FREQUENCY_DAYS else cfg.get("frequency", "weekly")
    cfg.update({"enabled": enabled, "frequency": frequency})
    if enabled:
        cfg["next_run_at"] = next_watch_run(frequency, datetime.now(UTC)).isoformat()
    else:
        cfg.pop("next_run_at", None)
    case.watch_config = cfg


async def last_activity(session: AsyncSession, case: Investigation) -> datetime:
    """Retention clock: case creation or the latest scan (manual, pivot or watch).

    Deliberately not ``updated_at``: that moves on any write, including the
    "reviewed" marker set by simply opening a case, and viewing must not
    keep personal data alive.
    """
    last_scan = await session.scalar(select(func.max(ScanRun.created_at)).where(ScanRun.case_id == case.id))
    return max(t for t in (case.created_at, last_scan) if t is not None)


async def last_scan_times(session: AsyncSession, case_ids: list[uuid.UUID] | None = None) -> dict[uuid.UUID, datetime]:
    """Latest scan creation time per case, in one query (for lists of cases)."""
    stmt = select(ScanRun.case_id, func.max(ScanRun.created_at)).group_by(ScanRun.case_id)
    if case_ids is not None:
        stmt = stmt.where(ScanRun.case_id.in_(case_ids))
    return dict((await session.execute(stmt)).all())


def purge_date_from(case: Investigation, last_scan: datetime | None) -> datetime | None:
    """Retention deadline given the case's latest scan time (see ``last_activity``)."""
    if case.permanently_active:
        return None
    start = max(t for t in (case.created_at, last_scan) if t is not None)
    return start + timedelta(days=case.retention_days)


async def purge_date(session: AsyncSession, case: Investigation) -> datetime | None:
    if case.permanently_active:
        return None
    return await last_activity(session, case) + timedelta(days=case.retention_days)


@dataclass
class TickResult:
    watch_started: list[str] = field(default_factory=list)
    purged: int = 0
    health_checks: list[str] = field(default_factory=list)


async def _start_watch_scans(session: AsyncSession, now: datetime, limit: int) -> list[str]:
    from app.jobs import enqueue_scan
    from app.services.scans import create_scan_run

    due = []
    for case in (await session.scalars(select(Investigation).where(Investigation.is_sample.is_(False)))).all():
        state = watch_state(case)
        if state["enabled"] and state["next_run_at"] and state["next_run_at"] <= now:
            due.append(case)
    _rng.shuffle(due)
    started = []
    for case in due[:limit]:
        busy = await session.scalar(
            select(ScanRun.id).where(ScanRun.case_id == case.id, ScanRun.status.in_(("queued", "running"))).limit(1)
        )
        state = watch_state(case)
        case.watch_config = {
            **(case.watch_config or {}),
            "next_run_at": next_watch_run(state["frequency"], now).isoformat(),
        }
        if busy:
            await session.commit()
            continue  # a scan is already in flight; try again next interval
        run = await create_scan_run(session, case, triggered_by="watch_mode")
        session.add(AccessLog(case_id=case.id, action="watch_scan", detail={"run_number": run.run_number}))
        await session.commit()
        enqueue_scan(run.id, "watch_mode")
        started.append(str(case.id))
    return started


async def _purge_expired(session: AsyncSession, now: datetime) -> int:
    from app.alerts import send_alert
    from app.services.cases import delete_case

    purged = 0
    last_scans = await last_scan_times(session)
    for case in (await session.scalars(select(Investigation))).all():
        when = purge_date_from(case, last_scans.get(case.id))
        if when is None or when > now:
            continue
        active = await session.scalar(
            select(ScanRun.id).where(ScanRun.case_id == case.id, ScanRun.status.in_(("queued", "running"))).limit(1)
        )
        if active:
            continue
        await delete_case(session, case.id, user_id=None, action="retention_purge", retention_days=case.retention_days)
        await session.commit()
        purged += 1
    if purged:
        await send_alert(f"retention: {purged} expired case(s) purged")
    return purged


async def _health_checks(session: AsyncSession, now: datetime) -> list[str]:
    from app.adapters.registry import get_adapter
    from app.jobs import enqueue_health_check, uses_rq
    from app.services.tools import run_health_check

    hours = get_settings().healthcheck_interval_hours
    if hours <= 0:
        return []
    checked = []
    for cfg in (await session.scalars(select(ToolConfig))).all():
        adapter = get_adapter(cfg.tool_name)
        if adapter is None or adapter.configured() is not None:
            continue
        # Only the circuit breaker's disabling is revisited; a human's is respected.
        if not cfg.enabled and not cfg.circuit_open:
            continue
        if cfg.last_health_check_at and now - cfg.last_health_check_at < timedelta(hours=hours):
            continue
        cfg.last_health_check_at = now  # claim it so the next tick doesn't repeat it
        await session.commit()
        if uses_rq():
            enqueue_health_check(cfg.tool_name)
        else:
            await run_health_check(session, cfg.tool_name)
        checked.append(cfg.tool_name)
    return checked


async def tick() -> TickResult:
    s = get_settings()
    now = datetime.now(UTC)
    result = TickResult()
    async with sessionmaker()() as session:
        result.watch_started = await _start_watch_scans(session, now, s.watch_max_per_tick)
        result.purged = await _purge_expired(session, now)
        result.health_checks = await _health_checks(session, now)
    return result


def _redis_lock():
    from app.jobs import redis_connection

    return redis_connection().lock(
        "unmask:scheduler", timeout=get_settings().scheduler_interval_seconds, blocking=False
    )


async def run_forever() -> None:
    """Tick loop for the inline backend (runs inside the web process)."""
    interval = get_settings().scheduler_interval_seconds
    while True:
        try:
            await tick()
        except Exception:
            log.exception("scheduler tick failed")
        await asyncio.sleep(interval)


def start_worker_thread() -> threading.Thread:
    """Tick loop for RQ workers; a Redis lock keeps multiple workers from double-ticking."""

    def _loop() -> None:
        import time

        interval = get_settings().scheduler_interval_seconds
        while True:
            lock = _redis_lock()
            try:
                if lock.acquire():
                    try:
                        asyncio.run(_tick_and_dispose())
                    finally:
                        try:
                            lock.release()
                        except Exception as exc:  # lock expired mid-tick: harmless
                            log.debug("scheduler lock already released: %s", exc)
            except Exception:
                log.exception("scheduler tick failed")
            time.sleep(interval)

    thread = threading.Thread(target=_loop, name="unmask-scheduler", daemon=True)
    thread.start()
    return thread


async def _tick_and_dispose() -> None:
    try:
        result = await tick()
        if result.watch_started or result.purged or result.health_checks:
            log.info(
                "scheduler: %d watch scan(s), %d purge(s), health checks: %s",
                len(result.watch_started), result.purged, ", ".join(result.health_checks) or "none",
            )  # fmt: skip
    finally:
        await dispose_engine()
