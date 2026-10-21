"""When each person last looked at each case, so a case can say what changed since.

A "visit" starts when someone opens a case more than VISIT_GAP after their last view, so
moving between tabs doesn't reset it: the strip saying what is new stays put for the
whole visit. Stored in the user's preferences (case id -> last, previous); a per-person
convenience, not an audit record (the audit log keeps case views).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.engine import NOT_SAME, SAME_AS
from app.models import Entity, Relation, ScanRun, User

VISIT_GAP = timedelta(minutes=30)
KEEP = 300


@dataclass
class SinceLastVisit:
    at: datetime
    findings: int
    links: int
    scans: int

    @property
    def any(self) -> bool:
        return bool(self.findings or self.links or self.scans)


def _parse(value) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except (TypeError, ValueError):
        return None


async def record_visit(user: User, case_id: uuid.UUID, now: datetime | None = None) -> datetime | None:
    """Note this view; return when the previous visit was (None on a first visit).

    Written through its own session, so it never commits or rolls back the request's work.
    """
    from app.db import sessionmaker

    now = now or datetime.now(UTC)
    key = str(case_id)
    async with sessionmaker()() as session:
        fresh = await session.get(User, user.id, with_for_update=True)
        if fresh is None:
            return None
        prefs = dict(fresh.preferences or {})
        visits = dict(prefs.get("visits") or {})
        entry = dict(visits.get(key) or {})
        last, prev = _parse(entry.get("last")), _parse(entry.get("prev"))
        if last is None or now - last > VISIT_GAP:
            prev = last
        entry = {"last": now.isoformat(), "prev": prev.isoformat() if prev else None}
        visits[key] = entry
        if len(visits) > KEEP:
            visits = dict(sorted(visits.items(), key=lambda kv: kv[1].get("last") or "")[-KEEP:])
        prefs["visits"] = visits
        fresh.preferences = prefs
        await session.commit()
    user.preferences = prefs
    return prev


async def since_last_visit(session: AsyncSession, case_id: uuid.UUID, since: datetime | None) -> SinceLastVisit | None:
    if since is None:
        return None
    findings = await session.scalar(
        select(func.count()).select_from(Entity).where(
            Entity.case_id == case_id, Entity.is_seed.is_(False), Entity.merged_into_id.is_(None),
            Entity.dismissed_flag.is_(False), Entity.first_seen > since,
        )
    )  # fmt: skip
    links = await session.scalar(
        select(func.count()).select_from(Relation).where(
            Relation.case_id == case_id, Relation.relation_type.not_in((SAME_AS, NOT_SAME)),
            Relation.created_at > since,
        )
    )  # fmt: skip
    scans = await session.scalar(
        select(func.count()).select_from(ScanRun).where(ScanRun.case_id == case_id, ScanRun.created_at > since)
    )
    return SinceLastVisit(since, findings or 0, links or 0, scans or 0)
