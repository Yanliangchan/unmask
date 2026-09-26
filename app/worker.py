"""RQ worker entrypoint: ``python -m app.worker``.

Runs as its own Railway service from the same image (``UNMASK_ROLE=worker``).
Each job gets a fresh event loop and database engine, disposed when it ends.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import timedelta

from app import crypto
from app.config import get_settings
from app.db import dispose_engine, sessionmaker

log = logging.getLogger("unmask.worker")


def _configure() -> None:
    s = get_settings()
    s.validate_for_startup()
    crypto.cipher.configure(s.data_keys, s.index_key)


async def _scan(run_id: uuid.UUID) -> None:
    from app.services.scans import execute_scan_run, mark_run_crashed

    try:
        await execute_scan_run(run_id)
    except Exception as exc:
        await mark_run_crashed(run_id, f"{exc.__class__.__name__}: {exc}")
        raise
    finally:
        await dispose_engine()


def run_scan_job(run_id: str) -> None:
    _configure()
    asyncio.run(_scan(uuid.UUID(run_id)))


def on_scan_failure(job, connection, exc_type, exc_value, tb) -> None:
    """RQ failure callback (timeouts, crashes before the scan could record them)."""
    from app.services.scans import mark_run_crashed

    async def _mark() -> None:
        try:
            await mark_run_crashed(uuid.UUID(job.args[0]), f"worker job failed: {exc_type.__name__}: {exc_value}")
        finally:
            await dispose_engine()

    _configure()
    asyncio.run(_mark())


def correlate_job(case_id: str) -> str:
    from app.correlation.engine import correlate_and_commit

    async def _run() -> str:
        try:
            async with sessionmaker()() as session:
                return (await correlate_and_commit(session, uuid.UUID(case_id))).summary()
        finally:
            await dispose_engine()

    _configure()
    return asyncio.run(_run())


def health_check_job(tool_name: str) -> str:
    from app.services.tools import run_health_check

    async def _check() -> str:
        try:
            async with sessionmaker()() as session:
                return (await run_health_check(session, tool_name)).status_label
        finally:
            await dispose_engine()

    _configure()
    return asyncio.run(_check())


async def _startup() -> None:
    from app.services.scans import fail_interrupted_runs
    from app.services.tools import sync_tool_config

    try:
        async with sessionmaker()() as session:
            await sync_tool_config(session)
            grace = timedelta(seconds=get_settings().scan_job_timeout_seconds + 600)
            reaped = await fail_interrupted_runs(session, older_than=grace)
            if reaped:
                log.warning("marked %d stale scan run(s) as failed", reaped)
    finally:
        await dispose_engine()


def main() -> None:
    from rq import Queue, Worker

    from app.jobs import QUEUES_BY_PRIORITY, redis_connection

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    _configure()
    asyncio.run(_startup())
    if get_settings().scheduler_enabled:
        from app.scheduler import start_worker_thread

        start_worker_thread()
    conn = redis_connection()
    queues = [Queue(name, connection=conn) for name in QUEUES_BY_PRIORITY]
    Worker(queues, connection=conn, name=None).work(with_scheduler=False)


if __name__ == "__main__":
    main()
