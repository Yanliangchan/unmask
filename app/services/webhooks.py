"""Signed outbound webhooks, for wiring UNMASK into other systems (SOAR, ticketing, chat bots).

Payloads say what happened and where to look, never what was found: a case id, a scan
number, counts, a link back. Like email and Slack copies, they carry no case names,
targets or findings, because the receiving system is outside UNMASK's access control.
A receiver that needs the data calls the API with its own key.

Every delivery is signed:

    X-Unmask-Event:      scan.finished
    X-Unmask-Delivery:   <uuid>
    X-Unmask-Timestamp:  <unix seconds>
    X-Unmask-Signature:  sha256=<hex HMAC-SHA256(secret, "<timestamp>.<raw body>")>

A receiver recomputes the HMAC over the timestamp and the raw body with the shared secret,
compares in constant time, and rejects timestamps more than five minutes old.

Delivery happens after the database commit, in the background; the URL must be a public
https address (checked on save and on every delivery, redirects not followed); a failed
delivery is retried twice and its status recorded on the webhook.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import WEBHOOK_EVENTS, Webhook

log = logging.getLogger(__name__)

# Tests swap this for an httpx.MockTransport, and RETRY_DELAYS for zeros.
transport: httpx.AsyncBaseTransport | None = None
RETRY_DELAYS = (2.0, 10.0)
MAX_HOOKS = 20
_pending: set[asyncio.Task] = set()


def sign(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode(), str(timestamp).encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify(secret: str, timestamp: int, body: bytes, signature: str, *, tolerance: int = 300) -> bool:
    """What a receiver does (and what the tests check)."""
    if abs(time.time() - timestamp) > tolerance:
        return False
    return hmac.compare_digest(sign(secret, timestamp, body), signature)


async def check_url(url: str) -> str | None:
    """A problem with this URL, or None. Public addresses only; https outside development."""
    from app.safefetch import BlockedURL
    from app.safefetch import check_url as public

    parts = urlsplit(url)
    if parts.scheme != "https" and get_settings().is_production:
        return "Webhook URLs must use https"
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return "Enter the full URL, starting with https://"
    if len(url) > 2000:
        return "That URL is too long"
    try:
        await public(url)
    except BlockedURL as exc:
        return f"That address can't receive webhooks: {exc}"
    return None


async def create(session: AsyncSession, *, url: str, events: list[str], user_id: uuid.UUID) -> tuple[Webhook, str]:
    events = sorted({e for e in events if e in WEBHOOK_EVENTS})
    if not events:
        raise ValueError("Choose at least one event")
    if problem := await check_url(url.strip()):
        raise ValueError(problem)
    count = len((await session.scalars(select(Webhook.id))).all())
    if count >= MAX_HOOKS:
        raise ValueError(f"At most {MAX_HOOKS} webhooks; remove one first")
    secret = "whsec_" + secrets.token_urlsafe(32)
    hook = Webhook(url=url.strip(), secret=secret, events=events, created_by=user_id)
    session.add(hook)
    await session.flush()
    return hook, secret


def emit(session: AsyncSession, name: str, data: dict) -> None:
    """Queue an event; it is delivered once the session commits (and dropped on rollback)."""
    if name not in WEBHOOK_EVENTS and name != "ping":
        raise ValueError(name)
    session.sync_session.info.setdefault("unmask_webhooks", []).append((name, data))


@event.listens_for(Session, "after_commit")
def _after_commit(session: Session) -> None:
    queued = session.info.pop("unmask_webhooks", None)
    if not queued:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    task = loop.create_task(_deliver_all(queued))
    _pending.add(task)
    task.add_done_callback(_pending.discard)


@event.listens_for(Session, "after_rollback")
def _after_rollback(session: Session) -> None:
    session.info.pop("unmask_webhooks", None)


async def drain() -> None:
    while _pending:
        await asyncio.gather(*list(_pending), return_exceptions=True)


def payload(name: str, data: dict) -> tuple[str, bytes]:
    delivery = str(uuid.uuid4())
    body = {"id": delivery, "event": name, "created_at": datetime.now(UTC).isoformat(), "data": data}
    return delivery, json.dumps(body, separators=(",", ":"), sort_keys=True).encode()


async def deliver(hook: Webhook, name: str, data: dict) -> str:
    """Send one event to one hook, with retries. Returns the status to record."""
    if problem := await check_url(hook.url):
        return f"refused: {problem}"[:80]
    delivery, body = payload(name, data)
    status = "failed"
    for attempt, delay in enumerate((0.0, *RETRY_DELAYS)):
        if delay:
            await asyncio.sleep(delay)
        ts = int(time.time())
        headers = {"Content-Type": "application/json", "User-Agent": "UNMASK-Webhooks/1",
                   "X-Unmask-Event": name, "X-Unmask-Delivery": delivery, "X-Unmask-Timestamp": str(ts),
                   "X-Unmask-Signature": sign(hook.secret, ts, body)}  # fmt: skip
        try:
            async with httpx.AsyncClient(transport=transport, timeout=10, follow_redirects=False) as client:
                resp = await client.post(hook.url, content=body, headers=headers)
            if 200 <= resp.status_code < 300:
                return f"delivered (HTTP {resp.status_code})"
            status = f"HTTP {resp.status_code}"
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                break  # the receiver refused it; retrying won't help
        except httpx.HTTPError as exc:
            # Never the exception text: it carries the URL, which is a credential.
            status = exc.__class__.__name__
        log.info("webhook delivery %s attempt %d: %s", delivery, attempt + 1, status)
    return f"failed: {status}"[:80]


async def _deliver_all(queued: list[tuple[str, dict]]) -> None:
    from app.db import sessionmaker

    try:
        async with sessionmaker()() as session:
            hooks = (await session.scalars(select(Webhook).where(Webhook.active.is_(True)))).all()
            for name, data in queued:
                for hook in hooks:
                    if name != "ping" and name not in (hook.events or []):
                        continue
                    status = await deliver(hook, name, data)
                    hook.last_status, hook.last_delivery_at = status, datetime.now(UTC)
                    hook.consecutive_failures = 0 if status.startswith("delivered") else hook.consecutive_failures + 1
            await session.commit()
    except Exception:
        log.exception("webhook delivery failed")
