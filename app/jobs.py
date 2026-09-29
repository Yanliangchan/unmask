"""Scan job dispatch.

Two backends, chosen by ``UNMASK_QUEUE``:

* ``inline`` — scans run as asyncio tasks inside the web process (dev, tests).
* ``rq`` — scans are queued in Redis and run by ``python -m app.worker``.

RQ workers drain queues in the order given, so priority is by queue: manual
scans go to ``unmask-high`` and always start before pivot-chain or watch-mode
work waiting in the lower queues.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid

from app.config import get_settings
from app.services.scans import execute_scan_run, mark_run_crashed

log = logging.getLogger(__name__)

QUEUE_HIGH, QUEUE_DEFAULT, QUEUE_LOW = "unmask-high", "unmask-default", "unmask-low"
QUEUES_BY_PRIORITY = [QUEUE_HIGH, QUEUE_DEFAULT, QUEUE_LOW]
QUEUE_FOR_TRIGGER = {
    "manual": QUEUE_HIGH,
    "pivot_chain": QUEUE_DEFAULT,
    "watch_mode": QUEUE_LOW,
    "health_check": QUEUE_LOW,
}

_running: set[asyncio.Task] = set()


def uses_rq() -> bool:
    return get_settings().queue_backend == "rq"


def redis_connection():
    from redis import Redis

    return Redis.from_url(get_settings().redis_url)


def scan_job_id(run_id: uuid.UUID) -> str:
    return f"scan-{run_id}"


async def _execute(run_id: uuid.UUID) -> None:
    try:
        await execute_scan_run(run_id)
    except Exception as exc:
        log.exception("scan %s crashed", run_id)
        await mark_run_crashed(run_id, f"{exc.__class__.__name__}: {exc}")


def enqueue_scan(run_id: uuid.UUID, triggered_by: str = "manual") -> str:
    """Dispatch a committed scan run. Returns the job id."""
    job_id = scan_job_id(run_id)
    if uses_rq():
        from rq import Callback, Queue

        queue = Queue(QUEUE_FOR_TRIGGER.get(triggered_by, QUEUE_DEFAULT), connection=redis_connection())
        queue.enqueue(
            "app.worker.run_scan_job",
            str(run_id),
            job_id=job_id,
            job_timeout=get_settings().scan_job_timeout_seconds,
            result_ttl=24 * 3600,
            failure_ttl=7 * 24 * 3600,
            on_failure=Callback("app.worker.on_scan_failure"),
        )
    else:
        task = asyncio.create_task(_execute(run_id), name=job_id)
        _running.add(task)
        task.add_done_callback(_running.discard)
    return job_id


def stop_scan(run_id: uuid.UUID) -> None:
    """Stop the job running a scan, wherever it runs. Best effort: the run is already marked cancelled."""
    job_id = scan_job_id(run_id)
    if not uses_rq():
        for task in list(_running):
            if task.get_name() == job_id:
                task.cancel()
        return
    try:
        from rq.command import send_stop_job_command
        from rq.job import Job

        conn = redis_connection()
        job = Job.fetch(job_id, connection=conn)
        if job.get_status() == "started":
            send_stop_job_command(conn, job_id)
        else:
            job.cancel()
    except Exception:
        log.warning("could not stop job %s", job_id, exc_info=True)


def enqueue_correlation(case_id: uuid.UUID) -> None:
    from rq import Queue

    Queue(QUEUE_HIGH, connection=redis_connection()).enqueue(
        "app.worker.correlate_job", str(case_id), job_timeout=1800, result_ttl=3600
    )


def enqueue_health_check(tool_name: str) -> None:
    from rq import Queue

    Queue(QUEUE_LOW, connection=redis_connection()).enqueue(
        "app.worker.health_check_job", tool_name, job_timeout=3600, result_ttl=3600
    )


_worker_cache: tuple[float, int | None] = (0.0, None)


def worker_count() -> int | None:
    """Live RQ workers (cached 15s); None when not using RQ or Redis is down."""
    global _worker_cache
    if not uses_rq():
        return None
    checked, count = _worker_cache
    if time.monotonic() - checked < 15:
        return count
    try:
        from rq import Worker

        count = Worker.count(connection=redis_connection())
    except Exception:
        count = None
    _worker_cache = (time.monotonic(), count)
    return count


async def wait_for_all() -> None:
    """Test helper: block until every in-flight inline scan finishes."""
    while _running:
        await asyncio.gather(*list(_running), return_exceptions=True)
