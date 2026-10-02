"""A small cache of profile-page verdicts, so one page is fetched once.

The same profile URL often comes from several tools in one scan (Sherlock,
Maigret and a web search all find github.com/janedoe), from pivot runs and
from rescans soon after. Each would otherwise download and classify the page
again. This keeps the *verdict* (status, reason, the short preview), never
the page body, for a limited time and number of entries, and makes concurrent
requests for the same page share one fetch.

Per process and per event loop; cleared when the app goes idle.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")

MAX_ENTRIES = 512
TTL_SECONDS = 30 * 60


class VerdictCache:
    def __init__(self, max_entries: int = MAX_ENTRIES, ttl: float = TTL_SECONDS) -> None:
        self.max_entries, self.ttl = max_entries, ttl
        self._done: OrderedDict[tuple, tuple[float, object]] = OrderedDict()
        self._inflight: dict[tuple, asyncio.Future] = {}
        self.hits = 0

    def get(self, key: tuple):
        item = self._done.get(key)
        if item is None:
            return None
        stored_at, value = item
        if time.monotonic() - stored_at > self.ttl:
            del self._done[key]
            return None
        self._done.move_to_end(key)
        return value

    def put(self, key: tuple, value) -> None:
        self._done[key] = (time.monotonic(), value)
        self._done.move_to_end(key)
        while len(self._done) > self.max_entries:
            self._done.popitem(last=False)

    async def get_or_fetch(self, key: tuple, fetch: Callable[[], Awaitable[T]],
                           cacheable: Callable[[T], bool] = lambda _: True) -> tuple[T, bool]:  # fmt: skip
        """(value, came_from_cache). Concurrent callers for one key share a single fetch."""
        cached = self.get(key)
        if cached is not None:
            self.hits += 1
            return cached, True
        pending = self._inflight.get(key)
        if pending is not None:
            self.hits += 1
            return await asyncio.shield(pending), True
        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._inflight[key] = fut
        try:
            value = await fetch()
        except BaseException as exc:
            fut.set_exception(exc)
            fut.exception()  # mark retrieved: waiters (if any) re-raise it themselves
            raise
        finally:
            self._inflight.pop(key, None)
        if cacheable(value):
            self.put(key, value)
        fut.set_result(value)
        return value, False

    def clear(self) -> None:
        self._done.clear()

    def __len__(self) -> int:
        return len(self._done)


_caches: dict[int, VerdictCache] = {}


def verdicts() -> VerdictCache:
    """The cache for the running event loop (each RQ job runs its own loop)."""
    key = id(asyncio.get_running_loop())
    cache = _caches.get(key)
    if cache is None:
        if len(_caches) > 8:
            _caches.clear()
        cache = _caches[key] = VerdictCache()
    return cache


def clear_all() -> None:
    _caches.clear()
