"""The case at a glance: what the evidence currently says, in one sentence and a few cards."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.engine import POSSIBLE_SAME
from app.models import Entity, Relation, ScanRun
from app.services.entities import LIKELY, POSSIBLE, hidden_reason

MAX_CARDS = 6


@dataclass
class ProfileCard:
    entity: Entity
    site: str
    handle: str
    title: str
    about: str
    location: str


@dataclass
class CaseSummary:
    headline: str
    detail: str
    cards: list[ProfileCard] = field(default_factory=list)
    other_likely: list[Entity] = field(default_factory=list)
    shown: int = 0
    possible: int = 0
    to_review: int = 0
    hidden: int = 0
    discarded: int = 0
    scanning: bool = False
    scanned: bool = False


def _card(e: Entity) -> ProfileCard:
    attrs = e.attributes or {}
    preview = attrs.get("preview") or {}
    profile = attrs.get("profile") or {}
    about = profile.get("bio") or preview.get("description") or ""
    location = profile.get("location") or profile.get("city") or profile.get("country") or ""
    title = profile.get("fullname") or profile.get("name") or preview.get("title") or ""
    return ProfileCard(
        entity=e,
        site=str(attrs.get("site") or attrs.get("host") or "Profile"),
        handle=str(attrs.get("username") or ""),
        title=str(title)[:80],
        about=str(about)[:160],
        location=str(location)[:60],
    )


def _is_likely(e: Entity) -> bool:
    return e.confirmed_flag or e.confidence >= LIKELY


async def case_summary(session: AsyncSession, case_id: uuid.UUID) -> CaseSummary:
    entities = [
        e
        for e in (await session.scalars(select(Entity).where(Entity.case_id == case_id))).all()
        if e.merged_into_id is None and not e.is_seed
    ]
    runs = (await session.scalars(select(ScanRun).where(ScanRun.case_id == case_id))).all()
    to_review = len(
        (
            await session.scalars(
                select(Relation.id).where(Relation.case_id == case_id, Relation.relation_type == POSSIBLE_SAME)
            )
        ).all()
    )
    discarded = sum(
        (tool.get("counts") or {}).get("rejected", 0)
        for run in runs
        for tool in ((run.failure_details or {}).get("_verification") or {}).values()
    )

    visible = [e for e in entities if hidden_reason(e) is None]
    hidden = sum(1 for e in entities if hidden_reason(e) in ("unverified", "weak"))
    likely = sorted((e for e in visible if _is_likely(e)), key=lambda e: (not e.confirmed_flag, -e.confidence))
    accounts = [e for e in likely if e.type == "account"]
    possible = sum(1 for e in visible if not _is_likely(e) and e.confidence >= POSSIBLE)
    scanning = any(r.status in ("queued", "running") for r in runs)

    s = CaseSummary(
        headline="",
        detail="",
        cards=[_card(e) for e in accounts[:MAX_CARDS]],
        other_likely=[e for e in likely if e.type != "account"][:6],
        shown=len(visible),
        possible=possible,
        to_review=to_review,
        hidden=hidden,
        discarded=discarded,
        scanning=scanning,
        scanned=bool(runs),
    )
    confirmed = sum(1 for e in likely if e.confirmed_flag)
    if accounts:
        sites = len(accounts)
        s.headline = f"Likely the same person on {sites} site{'s' if sites != 1 else ''}"
        s.detail = (
            f"{confirmed} confirmed by you." if confirmed else "None confirmed yet: tick the ones you've checked."
        )
    elif likely:
        s.headline = f"{len(likely)} likely finding{'s' if len(likely) != 1 else ''}, no matching profiles yet"
        s.detail = "Likely emails, names or domains are listed below."
    elif possible:
        s.headline = "No strong matches yet"
        s.detail = f"{possible} possible finding{'s' if possible != 1 else ''} need a closer look."
    elif scanning:
        s.headline = "Scanning"
        s.detail = "Results appear here as each tool finishes."
    elif s.scanned:
        s.headline = "Nothing convincing found"
        s.detail = "Try adding context (a city, an employer) or another identifier, then scan again."
    else:
        s.headline = "Not scanned yet"
        s.detail = "Run a scan to start."
    if scanning and s.headline != "Scanning":
        s.detail += " Still scanning; this will update."
    return s
