"""API keys for /api/v1.

A key looks like ``umk_<prefix>_<secret>``. The prefix identifies it in lists and in the
audit log; only a SHA-256 of the whole key is stored (it is 256 bits of randomness, so a
plain hash is enough, as for share links). Keys carry scopes, expire, and can be revoked;
they act as the user who made them and see exactly the cases that user can see.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import API_SCOPES, ApiKey, User

MAX_DAYS = 365
MAX_KEYS_PER_USER = 10
RATE_PER_MINUTE = 120


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


async def create_key(
    session: AsyncSession, user: User, *, name: str, scopes: list[str], days: int
) -> tuple[ApiKey, str]:
    scopes = sorted({s for s in scopes if s in API_SCOPES})
    if not scopes:
        raise ValueError("Choose at least one permission for the key")
    if not name.strip():
        raise ValueError("Give the key a name, such as the system that will use it")
    live = (
        await session.scalars(
            select(ApiKey).where(
                ApiKey.user_id == user.id, ApiKey.revoked_at.is_(None), ApiKey.expires_at > datetime.now(UTC)
            )  # fmt: skip
        )
    ).all()
    if len(live) >= MAX_KEYS_PER_USER:
        raise ValueError(f"You already have {MAX_KEYS_PER_USER} active keys; revoke one first")
    prefix = secrets.token_hex(4)
    token = f"umk_{prefix}_{secrets.token_urlsafe(32)}"
    key = ApiKey(user_id=user.id, name=name.strip()[:80], prefix=prefix, key_hash=_hash(token), scopes=scopes,
                 expires_at=datetime.now(UTC) + timedelta(days=max(1, min(MAX_DAYS, days))))  # fmt: skip
    session.add(key)
    await session.flush()
    return key, token


async def authenticate(session: AsyncSession, token: str) -> tuple[ApiKey, User] | None:
    if not token.startswith("umk_") or len(token) > 120:
        return None
    key = await session.scalar(select(ApiKey).where(ApiKey.key_hash == _hash(token)))
    if key is None or key.revoked_at is not None or key.expires_at <= datetime.now(UTC):
        return None
    user = await session.get(User, key.user_id)
    if user is None or not user.is_active:
        return None
    return key, user


async def keys_for(session: AsyncSession, user: User) -> list[ApiKey]:
    return list(
        (
            await session.scalars(select(ApiKey).where(ApiKey.user_id == user.id).order_by(ApiKey.created_at.desc()))
        ).all()
    )


class RateLimiter:
    """Requests per key per rolling minute, in this process (a deployment behind several
    processes gets that many times the limit; the daily scan quota is the hard bound)."""

    def __init__(self, per_minute: int = RATE_PER_MINUTE):
        self.per_minute = per_minute
        self.hits: dict[str, deque] = defaultdict(deque)

    def allow(self, key_id: str) -> bool:
        now = time.monotonic()
        q = self.hits[key_id]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return False
        q.append(now)
        if len(self.hits) > 10_000:
            self.hits.clear()
        return True


limiter = RateLimiter()
