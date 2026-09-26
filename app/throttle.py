"""Per-tool concurrency limits that hold across scans and worker processes.

``tool_config.max_concurrent`` caps how many runs of one tool may be in flight
at once, platform-wide. With the RQ backend several worker processes share one
Redis-backed lease set; the inline backend (dev/tests) uses in-process
semaphores. Leases expire, so a killed worker can never wedge a tool.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from contextlib import asynccontextmanager

from app.config import get_settings

_ACQUIRE = """
local key, now, expiry, limit, token = KEYS[1], tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), ARGV[4]
redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
if redis.call('ZCARD', key) < limit then
  redis.call('ZADD', key, expiry, token)
  redis.call('EXPIRE', key, math.ceil(expiry - now) + 60)
  return 1
end
return 0
"""

_local: dict[tuple[int, str], asyncio.Semaphore] = {}


def _local_semaphore(tool: str, limit: int) -> asyncio.Semaphore:
    key = (id(asyncio.get_running_loop()), tool)
    sem = _local.get(key)
    if sem is None:
        sem = _local[key] = asyncio.Semaphore(max(1, limit))
    return sem


@asynccontextmanager
async def tool_slot(tool: str, limit: int, lease_seconds: float, delay_seconds: float = 0):
    """Hold one of ``limit`` slots for ``tool``; wait ``delay_seconds`` before releasing it."""
    settings = get_settings()
    if settings.queue_backend != "rq":
        async with _local_semaphore(tool, limit):
            yield
            if delay_seconds:
                await asyncio.sleep(delay_seconds)
        return

    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(settings.redis_url)
    key, token = f"unmask:tool-slots:{tool}", uuid.uuid4().hex
    try:
        script = client.register_script(_ACQUIRE)
        while True:
            now = time.time()
            if await script(keys=[key], args=[now, now + lease_seconds, max(1, limit), token]):
                break
            await asyncio.sleep(1)
        try:
            yield
            if delay_seconds:
                await asyncio.sleep(delay_seconds)
        finally:
            await client.zrem(key, token)
    finally:
        await client.aclose()
