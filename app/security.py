"""Authentication, CSRF and login rate limiting."""

from __future__ import annotations

import secrets
import time
import uuid
from collections import defaultdict

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_session
from app.models import User

_hasher = PasswordHasher()
# Verified against when the email is unknown, so response time does not reveal
# which accounts exist.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerificationError, InvalidHashError):
        return False


# --- CSRF -------------------------------------------------------------------


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


async def verify_csrf(request: Request) -> None:
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    expected = request.session.get("csrf")
    supplied = request.headers.get("x-csrf-token")
    if not supplied:
        form = await request.form()
        supplied = form.get("csrf_token")  # type: ignore[assignment]
    if not expected or not supplied or not secrets.compare_digest(str(expected), str(supplied)):
        raise HTTPException(status_code=403, detail="CSRF token missing or invalid")


# --- Login rate limiting ----------------------------------------------------


class LoginRateLimiter:
    """Fixed-window limiter. Uses Redis when reachable, memory otherwise."""

    def __init__(self) -> None:
        self._memory: dict[str, list[float]] = defaultdict(list)
        self._redis = None
        self._redis_checked = False

    def _client(self):
        if not self._redis_checked:
            self._redis_checked = True
            try:
                import redis

                client = redis.Redis.from_url(get_settings().redis_url, socket_connect_timeout=0.5)
                client.ping()
                self._redis = client
            except Exception:
                self._redis = None
        return self._redis

    def _keys(self, ip: str, email: str) -> dict[str, int]:
        """Key -> max failures. Per-IP is looser so a shared NAT isn't locked out."""
        limit = get_settings().login_max_attempts
        return {f"unmask:login:email:{email.lower()}": limit, f"unmask:login:ip:{ip}": limit * 4}

    def is_blocked(self, ip: str, email: str) -> bool:
        s = get_settings()
        client = self._client()
        for key, limit in self._keys(ip, email).items():
            if client is not None:
                count = int(client.get(key) or 0)
            else:
                now = time.monotonic()
                self._memory[key] = [t for t in self._memory[key] if now - t < s.login_window_seconds]
                count = len(self._memory[key])
            if count >= limit:
                return True
        return False

    def record_failure(self, ip: str, email: str) -> None:
        s = get_settings()
        client = self._client()
        for key in self._keys(ip, email):
            if client is not None:
                pipe = client.pipeline()
                pipe.incr(key)
                pipe.expire(key, s.login_window_seconds, nx=True)
                pipe.execute()
            else:
                self._memory[key].append(time.monotonic())

    def reset(self, ip: str, email: str) -> None:
        client = self._client()
        for key in self._keys(ip, email):
            if client is not None:
                client.delete(key)
            self._memory.pop(key, None)


login_limiter = LoginRateLimiter()


# --- Current user -----------------------------------------------------------


class LoginRequired(Exception):
    pass


class TermsRequired(Exception):
    """Signed in, but hasn't accepted the current Terms of Service yet."""


async def current_user_optional(request: Request, session: AsyncSession = Depends(get_session)) -> User | None:
    raw = request.session.get("user_id")
    if not raw:
        return None
    try:
        user_id = uuid.UUID(raw)
    except ValueError:
        request.session.clear()
        return None
    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        request.session.clear()
        return None
    return user


async def current_user(user: User | None = Depends(current_user_optional)) -> User:
    from app.legal import needs_acceptance

    if user is None:
        raise LoginRequired()
    if needs_acceptance(user):
        raise TermsRequired()
    return user


async def ensure_admin_user(session: AsyncSession) -> None:
    """Create the bootstrap admin from env vars if no users exist yet."""
    s = get_settings()
    if not s.admin_email or not s.admin_password:
        return
    existing = await session.scalar(select(User.id).limit(1))
    if existing is not None:
        return
    session.add(
        User(
            email=s.admin_email.strip().lower(),
            display_name="Admin",
            password_hash=hash_password(s.admin_password),
            is_admin=True,
        )
    )
    await session.commit()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"
