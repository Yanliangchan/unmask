"""Scan job dispatch.

Phase 1 runs scans as in-process asyncio tasks. Phase 2 swaps this module's
internals for an RQ queue backed by Redis with a dedicated worker service;
callers only ever use ``enqueue_scan``.
"""

from __future__ import annotations

import asyncio
import logging
import uuid

from app.services.scans import execute_scan_run, mark_run_crashed

log = logging.getLogger(__name__)

_running: set[asyncio.Task] = set()


async def _execute(run_id: uuid.UUID) -> None:
    try:
        await execute_scan_run(run_id)
    except Exception as exc:
        log.exception("scan %s crashed", run_id)
        await mark_run_crashed(run_id, f"{exc.__class__.__name__}: {exc}")


def enqueue_scan(run_id: uuid.UUID) -> None:
    task = asyncio.create_task(_execute(run_id), name=f"scan-{run_id}")
    _running.add(task)
    task.add_done_callback(_running.discard)


async def wait_for_all() -> None:
    """Test helper: block until every in-flight scan finishes."""
    while _running:
        await asyncio.gather(*list(_running), return_exceptions=True)
