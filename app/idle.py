"""Going quiet when nobody is using the app.

While there are requests or scans, the web process runs normally: the
scheduler ticks (inline queue only) and the database pool stays open. After
``UNMASK_IDLE_SECONDS`` with no request in flight, no request received, no scan
running and no notification being delivered, it:

* stops the scheduler loop,
* closes every database connection,
* hands freed heap back to the OS,

and then waits without any timer until the next request wakes it. A process in
that state sends no network traffic, so a host that sleeps idle services
(Railway App Sleeping) can stop it entirely. The next request restarts the
scheduler, whose first tick runs straight away and catches up on anything that
came due (watch scans, retention purges, health checks).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable, Coroutine
from typing import Any

log = logging.getLogger(__name__)


class IdleMonitor:
    def __init__(self, idle_seconds: float, scheduler: Callable[[], Coroutine[Any, Any, None]] | None = None) -> None:
        self.idle_seconds = max(1.0, float(idle_seconds))
        self._scheduler_factory = scheduler
        self._scheduler: asyncio.Task | None = None
        self._monitor: asyncio.Task | None = None
        self._woken = asyncio.Event()
        self.last_seen = time.monotonic()
        self.in_flight = 0
        self.quiet = False
        self.quiet_count = 0

    # --- lifecycle --------------------------------------------------------------------

    def start(self) -> None:
        self._start_scheduler()
        self._monitor = asyncio.create_task(self._run(), name="unmask-idle")

    async def stop(self) -> None:
        for task in (self._monitor, self._scheduler):
            if task is not None:
                task.cancel()
        for task in (self._monitor, self._scheduler):
            if task is not None:
                with contextlib.suppress(asyncio.CancelledError, Exception):
                    await task
        self._monitor = self._scheduler = None

    # --- requests ---------------------------------------------------------------------

    def request_started(self) -> None:
        self.in_flight += 1
        self.last_seen = time.monotonic()
        if self.quiet:
            self.quiet = False
            log.info("request after idle: resuming background work")
            self._start_scheduler()
            self._woken.set()

    def request_finished(self) -> None:
        self.in_flight = max(0, self.in_flight - 1)
        self.last_seen = time.monotonic()

    # --- internals --------------------------------------------------------------------

    def _start_scheduler(self) -> None:
        if self._scheduler_factory is not None and (self._scheduler is None or self._scheduler.done()):
            self._scheduler = asyncio.create_task(self._scheduler_factory(), name="unmask-scheduler")

    def busy(self) -> bool:
        from app import jobs, scheduler
        from app.services import notifications

        return bool(self.in_flight or jobs._running or notifications._pending_tasks or scheduler.ticking)

    async def _run(self) -> None:
        while True:
            if self.quiet:
                self._woken.clear()
                await self._woken.wait()
                continue
            remaining = self.last_seen + self.idle_seconds - time.monotonic()
            if remaining > 0:
                await asyncio.sleep(min(remaining + 0.05, self.idle_seconds))
                continue
            if self.busy():
                self.last_seen = time.monotonic()
                continue
            await self.go_quiet()

    async def go_quiet(self) -> None:
        from app.db import dispose_engine
        from app.memory import rss_mb, trim

        seen = self.last_seen
        if self._scheduler is not None:
            self._scheduler.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._scheduler
            self._scheduler = None
        await dispose_engine()
        trim()
        if self.in_flight or self.last_seen != seen:
            # A request arrived while we were winding down: carry on as normal.
            self._start_scheduler()
            return
        self.quiet = True
        self.quiet_count += 1
        log.info("idle for %ss: scheduler stopped, database connections closed (%.0f MB resident)",
                 int(self.idle_seconds), rss_mb())  # fmt: skip


monitor: IdleMonitor | None = None
