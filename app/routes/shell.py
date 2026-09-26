"""Context shared by every page in a case (header, scan status, tab bar)."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.engine import POSSIBLE_SAME
from app.jobs import worker_count
from app.models import Entity, Investigation, PivotLog, Relation, ScanRun, User
from app.pivots.engine import auto_pivot_enabled
from app.scheduler import watch_state
from app.web import Seo

TABS = [
    ("entities", "Entities", ""),
    ("graph", "Graph", "/graph"),
    ("timeline", "Timeline", "/timeline"),
    ("pivots", "Pivots", "/pivots"),
    ("settings", "Settings", "/settings"),
]


async def case_shell(session: AsyncSession, case: Investigation, user: User, tab: str) -> dict:
    latest = await session.scalar(
        select(ScanRun).where(ScanRun.case_id == case.id).order_by(ScanRun.run_number.desc()).limit(1)
    )
    entity_count = await session.scalar(
        select(func.count()).select_from(Entity).where(Entity.case_id == case.id, Entity.merged_into_id.is_(None))
    )
    pivot_count = await session.scalar(select(func.count()).select_from(PivotLog).where(PivotLog.case_id == case.id))
    review_count = await session.scalar(
        select(func.count())
        .select_from(Relation)
        .where(Relation.case_id == case.id, Relation.relation_type == POSSIBLE_SAME)
    )
    label = dict((k, v) for k, v, _ in TABS)[tab]
    path = f"/cases/{case.id}" + dict((k, p) for k, _, p in TABS)[tab]
    return {
        "seo": Seo(title=case.name if tab == "entities" else f"{label} · {case.name}", path=path),
        "user": user,
        "case": case,
        "tab": tab,
        "tabs": TABS,
        "latest_run": latest,
        "run": latest,
        "workers": worker_count(),
        "watch": watch_state(case),
        "auto_pivot": auto_pivot_enabled(case),
        "counts": {"entities": entity_count, "pivots": pivot_count, "review": review_count},
    }
