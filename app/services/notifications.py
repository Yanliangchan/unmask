"""Notifications: in the app, and optionally by email and to a Slack webhook.

In-app notifications may name the case ("3 new findings in Vendor check"),
because only people who can open the case see them. Copies sent outside the
app (email, Slack) never carry case names or identifiers: case names often
contain the subject's name, and a Slack channel or a mailbox is not
access-controlled by UNMASK. They say what happened and link back in.

Outside delivery runs after the database commit, in the background, so a slow
mail server or webhook never holds up a scan or a request.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
import ssl
import uuid
from dataclasses import dataclass
from email.message import EmailMessage
from urllib.parse import urlsplit

import httpx
from sqlalchemy import event, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Entity, Investigation, Notification, ScanRun, User

log = logging.getLogger(__name__)

# kind -> (label shown in settings, generic text used outside the app)
KINDS: dict[str, tuple[str, str]] = {
    "scan_finished": ("A scan I can see finishes", "A scan finished."),
    "watch_changes": ("Watch mode finds something new", "Watch mode found new results in one of your cases."),
    "mention": ("Someone mentions me in a note", "You were mentioned in a note."),
    "shared": ("A case is shared with me", "A case was shared with you."),
}
DEFAULT_KINDS = list(KINDS)
# Incoming-webhook hosts accepted for the Slack channel (Slack, and Discord's Slack-compatible endpoint).
WEBHOOK_HOSTS = ("hooks.slack.com", "discord.com", "discordapp.com")

# Tests swap this for an httpx.MockTransport, and ``sent_mail`` collects mail instead of sending it.
transport: httpx.AsyncBaseTransport | None = None
sent_mail: list[EmailMessage] | None = None

_pending_tasks: set[asyncio.Task] = set()


@dataclass(frozen=True)
class Outgoing:
    user_id: uuid.UUID
    kind: str
    url: str | None


def prefs_for(user: User) -> dict:
    """The user's notification settings with defaults filled in."""
    raw = (user.preferences or {}).get("notify") or {}
    return {
        "email": bool(raw.get("email", False)),
        "slack": bool(raw.get("slack", bool(user.slack_webhook))),
        "kinds": [k for k in raw.get("kinds", DEFAULT_KINDS) if k in KINDS],
    }


def valid_webhook(url: str) -> str | None:
    """None if the URL is an acceptable incoming webhook, else why not.

    Only known webhook hosts over HTTPS are accepted, so the setting can't be
    used to make the server call arbitrary internal addresses.
    """
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or not parts.hostname:
        return "The webhook URL must start with https://"
    if parts.hostname not in WEBHOOK_HOSTS or parts.port not in (None, 443):
        return "Use a Slack incoming-webhook URL (https://hooks.slack.com/services/…)"
    return None


def email_configured() -> bool:
    s = get_settings()
    return bool(s.smtp_host and s.smtp_from)


async def notify(
    session: AsyncSession, user_id: uuid.UUID, *, kind: str, text: str, url: str | None = None,
    case_id: uuid.UUID | None = None,
) -> Notification:  # fmt: skip
    """Record an in-app notification; outside copies go out once the session commits."""
    n = Notification(user_id=user_id, case_id=case_id, kind=kind, text=text[:300], url=url)
    session.add(n)
    session.sync_session.info.setdefault("unmask_outbox", []).append(Outgoing(user_id, kind, url))
    return n


async def notify_members(
    session: AsyncSession, case: Investigation, *, kind: str, text: str, url: str | None = None,
    exclude: uuid.UUID | None = None,
) -> int:  # fmt: skip
    count = 0
    for uid in {case.owner_id, *(case.shared_with or [])}:
        if uid and uid != exclude:
            await notify(session, uid, kind=kind, text=text, url=url, case_id=case.id)
            count += 1
    return count


@event.listens_for(Session, "after_commit")
def _after_commit(session: Session) -> None:
    outbox = session.info.pop("unmask_outbox", None)
    if not outbox:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    task = loop.create_task(deliver(outbox))
    _pending_tasks.add(task)
    task.add_done_callback(_pending_tasks.discard)


@event.listens_for(Session, "after_rollback")
def _after_rollback(session: Session) -> None:
    session.info.pop("unmask_outbox", None)


async def drain() -> None:
    """Wait for outside deliveries in flight (tests, and worker shutdown)."""
    while _pending_tasks:
        await asyncio.gather(*list(_pending_tasks), return_exceptions=True)


async def deliver(outbox: list[Outgoing]) -> None:
    from app.db import sessionmaker

    try:
        async with sessionmaker()() as session:
            users = {
                u.id: u
                for u in (await session.scalars(select(User).where(User.id.in_({o.user_id for o in outbox})))).all()
            }
    except Exception:
        log.exception("could not load users for notification delivery")
        return
    base = get_settings().public_base_url.rstrip("/")
    for item in outbox:
        user = users.get(item.user_id)
        if user is None or not user.is_active:
            continue
        prefs = prefs_for(user)
        if item.kind not in prefs["kinds"]:
            continue
        text = KINDS.get(item.kind, ("", "There is something new in UNMASK."))[1]
        link = f"{base}{item.url}" if item.url else base
        if prefs["slack"] and user.slack_webhook:
            await send_slack(user.slack_webhook, f"{text} {link}")
        if prefs["email"] and email_configured():
            await send_email(user.email, text, f"{text}\n\nOpen UNMASK: {link}\n\n"
                             "You get this because of your notification settings in UNMASK.")  # fmt: skip


async def send_slack(url: str, text: str) -> bool:
    if valid_webhook(url):
        return False
    try:
        async with httpx.AsyncClient(transport=transport, timeout=8, follow_redirects=False) as client:
            resp = await client.post(url, json={"text": text, "content": text})
            resp.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        log.warning("notification webhook failed: %s", exc.__class__.__name__)
        return False


async def send_email(to: str, subject: str, body: str) -> bool:
    s = get_settings()
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = s.smtp_from, to, f"[UNMASK] {subject}"
    msg.set_content(body)
    if sent_mail is not None:
        sent_mail.append(msg)
        return True

    def _send() -> None:
        ctx = ssl.create_default_context()
        if s.smtp_port == 465:
            with smtplib.SMTP_SSL(s.smtp_host, s.smtp_port, timeout=15, context=ctx) as smtp:
                if s.smtp_user:
                    smtp.login(s.smtp_user, s.smtp_password)
                smtp.send_message(msg)
            return
        with smtplib.SMTP(s.smtp_host, s.smtp_port, timeout=15) as smtp:
            smtp.starttls(context=ctx)
            if s.smtp_user:
                smtp.login(s.smtp_user, s.smtp_password)
            smtp.send_message(msg)

    try:
        await asyncio.to_thread(_send)
        return True
    except (OSError, smtplib.SMTPException) as exc:
        log.warning("notification email failed: %s", exc.__class__.__name__)
        return False


async def unread_count(session: AsyncSession, user_id: uuid.UUID) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(Notification)
            .where(Notification.user_id == user_id, Notification.read_at.is_(None))
        )
        or 0
    )


async def recent(session: AsyncSession, user_id: uuid.UUID, limit: int = 50) -> list[Notification]:
    return list(
        (
            await session.scalars(
                select(Notification)
                .where(Notification.user_id == user_id)
                .order_by(Notification.created_at.desc())
                .limit(limit)
            )
        ).all()
    )


async def mark_all_read(session: AsyncSession, user_id: uuid.UUID) -> None:
    await session.execute(
        update(Notification)
        .where(Notification.user_id == user_id, Notification.read_at.is_(None))
        .values(read_at=func.now())
    )


async def notify_scan_finished(session: AsyncSession, run: ScanRun) -> None:
    """Tell a case's members a scan finished and how much it newly found.

    Follow-up (pivot) runs are part of the scan that started them, so they
    don't notify on their own. Watch-mode scans only notify when they found
    something new; a quiet weekly check isn't news.
    """
    if run.triggered_by not in ("manual", "watch_mode"):
        return
    case = await session.get(Investigation, run.case_id)
    if case is None or case.is_sample:
        return
    if run.status in ("completed", "partial") and case.owner_id:
        # The owner's own work has results now: the made-up sample case has done its job.
        from app.services.home import retire_sample

        if await retire_sample(session, case.owner_id):
            # "system" isn't a user-selectable kind, so it stays in the app (no email or Slack copy).
            await notify(session, case.owner_id, kind="system", url="/",
                         text="The sample case was removed now that your first case has results")  # fmt: skip
    since = run.started_at or run.created_at
    new = int(
        await session.scalar(
            select(func.count())
            .select_from(Entity)
            .where(
                Entity.case_id == case.id,
                Entity.is_seed.is_(False),
                Entity.merged_into_id.is_(None),
                Entity.first_seen >= since,
            )
        )
        or 0
    )
    found = f"{new} new finding{'s' if new != 1 else ''}" if new else "nothing new"
    n_failed = len(run.tools_failed or [])
    failed = f", {n_failed} tool{'s' if n_failed != 1 else ''} failed" if n_failed else ""
    if run.triggered_by == "watch_mode":
        if not new:
            return
        await notify_members(session, case, kind="watch_changes", url=f"/cases/{case.id}/timeline",
                             text=f"Watch mode: {found} in {case.name}{failed}")  # fmt: skip
        return
    await notify_members(session, case, kind="scan_finished", url=f"/cases/{case.id}",
                         text=f"Scan {run.run_number} of {case.name} finished: {found}{failed}")  # fmt: skip
