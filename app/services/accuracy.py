"""What the analysts' decisions say about each site and about the scores.

Every "Confirm" and "Not them" on an account is a label: this site's hit was
(or wasn't) the subject. Counted per site across all cases, those labels
show which sites' hits deserve trust, and scoring uses them. Only counts per
site host are kept, never case content.

The same labels also check the scores themselves: of the findings scored
"Likely", how many did analysts actually confirm?
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlparse

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Entity

# Beta(2, 2): before any decisions a site is assumed right half the time, and a
# handful of decisions only nudges it.
PRIOR_HITS, PRIOR_MISSES = 2, 2
MIN_DECISIONS = 3
DISMISS_REASONS = {
    "different_person": "Different person",
    "not_a_profile": "Not a real profile",
    "bot_or_spam": "Bot or spam account",
    "other": "Other",
}
# (label, low, high): the same bands the UI uses for Likely / Possible / Unlikely.
BANDS = [("Likely", 0.7, 1.01), ("Possible", 0.45, 0.7), ("Unlikely", 0.0, 0.45)]


def site_host(url: str) -> str | None:
    host = (urlparse(url.strip()).hostname or "").lower()
    return host.removeprefix("www.").removeprefix("m.") or None


@dataclass
class SiteStat:
    host: str
    confirmed: int = 0
    dismissed: int = 0
    reasons: Counter = field(default_factory=Counter)

    @property
    def decisions(self) -> int:
        return self.confirmed + self.dismissed

    @property
    def precision(self) -> float:
        return (self.confirmed + PRIOR_HITS) / (self.decisions + PRIOR_HITS + PRIOR_MISSES)

    @property
    def raw_precision(self) -> float | None:
        return self.confirmed / self.decisions if self.decisions else None


def site_factor(stat: SiteStat | None) -> tuple[float, str | None]:
    """Multiplier for an account's prior from its site's track record (0.6x to 1.4x)."""
    if stat is None or stat.decisions < MIN_DECISIONS:
        return 1.0, None
    factor = 0.6 + 0.8 * stat.precision
    note = f"{stat.host} hits were confirmed {stat.confirmed} of {stat.decisions} times in past reviews"
    return factor, note


async def site_stats(session: AsyncSession) -> dict[str, SiteStat]:
    rows = await session.execute(
        select(Entity.site_host, Entity.confirmed_flag, Entity.dismissed_flag, Entity.dismiss_reason).where(
            Entity.type == "account",
            Entity.site_host.is_not(None),
            Entity.merged_into_id.is_(None),
            Entity.is_seed.is_(False),
            or_(Entity.confirmed_flag.is_(True), Entity.dismissed_flag.is_(True)),
        )
    )
    stats: dict[str, SiteStat] = {}
    for host, confirmed, dismissed, reason in rows.all():
        s = stats.setdefault(host, SiteStat(host))
        if dismissed:
            s.dismissed += 1
            s.reasons[reason or "other"] += 1
        elif confirmed:
            s.confirmed += 1
    return stats


def model_score(e: Entity) -> float:
    """The score before any analyst override (confirmed findings display 1.0)."""
    return float((e.field_confidence or {}).get("evidence.model_score", e.confidence))


@dataclass
class Band:
    label: str
    decided: int = 0
    confirmed: int = 0

    @property
    def rate(self) -> float | None:
        return self.confirmed / self.decided if self.decided else None


@dataclass
class ToolStat:
    tool: str
    confirmed: int = 0
    dismissed: int = 0

    @property
    def rate(self) -> float | None:
        n = self.confirmed + self.dismissed
        return self.confirmed / n if n else None


@dataclass
class AccuracyReport:
    bands: list[Band]
    sites: list[SiteStat]
    tools: list[ToolStat]
    decided: int
    reasons: Counter


async def accuracy_report(session: AsyncSession, case_ids: list | None = None) -> AccuracyReport:
    stmt = select(Entity).where(
        Entity.merged_into_id.is_(None),
        Entity.is_seed.is_(False),
        Entity.source_tool != "analyst",
        or_(Entity.confirmed_flag.is_(True), Entity.dismissed_flag.is_(True)),
    )
    if case_ids is not None:
        stmt = stmt.where(Entity.case_id.in_(case_ids))
    decided = (await session.scalars(stmt)).all()
    bands = [Band(label) for label, _, _ in BANDS]
    tools: dict[str, ToolStat] = {}
    reasons: Counter = Counter()
    for e in decided:
        score = model_score(e)
        band = next(b for b, (_, lo, hi) in zip(bands, BANDS, strict=True) if lo <= score < hi)
        band.decided += 1
        t = tools.setdefault(e.source_tool, ToolStat(e.source_tool))
        if e.dismissed_flag:
            t.dismissed += 1
            reasons[e.dismiss_reason or "other"] += 1
        else:
            band.confirmed += 1
            t.confirmed += 1
    sites = sorted((await site_stats(session)).values(), key=lambda s: (-s.decisions, s.host))
    return AccuracyReport(
        bands=bands,
        sites=sites,
        tools=sorted(tools.values(), key=lambda t: t.tool),
        decided=len(decided),
        reasons=reasons,
    )
