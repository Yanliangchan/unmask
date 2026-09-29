"""In-app notifications, optionally copied to a Slack-compatible webhook.

Notification text never carries identifiers (no emails, usernames or names of
subjects): "3 new findings in Vendor check", not what they are. The link leads
back into the app, where access control applies.
"""

from __future__ import annotations

import logging
import uuid

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Notification

log = logging.getLogger(__name__)


async def notify(
    session: AsyncSession, user_id: uuid.UUID, *, kind: str, text: str, url: str | None = None,
    case_id: uuid.UUID | None = None,
) -> Notification:  # fmt: skip
    n = Notification(user_id=user_id, case_id=case_id, kind=kind, text=text[:300], url=url)
    session.add(n)
    return n


async def unread_count(session: AsyncSession, user_id: uuid.UUID) -> int:
    return int(
        await session.scalar(
            select(func.count())
            .select_from(Notification)
            .where(Notification.user_id == user_id, Notification.read_at.is_(None))
        )
        or 0
    )


async def mark_all_read(session: AsyncSession, user_id: uuid.UUID) -> None:
    await session.execute(
        update(Notification)
        .where(Notification.user_id == user_id, Notification.read_at.is_(None))
        .values(read_at=func.now())
    )
