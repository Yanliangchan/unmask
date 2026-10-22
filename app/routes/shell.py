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

# Four sections, each with the pages that belong to it; Settings sits apart (the gear).
SECTIONS = [
    ("findings", "Findings", [("entities", "Entities", ""), ("web", "Web results", "/web")]),
    ("graph", "Graph", [("graph", "Graph", "/graph"), ("timeline", "Compare scans", "/timeline")]),
    (
        "log",
        "Log",
        [("log", "Working log", "/log"), ("pivots", "Follow-ups", "/pivots"), ("activity", "Activity", "/activity")],
    ),
    ("report", "Report", [("report", "Report", "/deliver")]),
]
TABS = [t for _, _, subs in SECTIONS for t in subs] + [("settings", "Settings", "/settings")]
SECTION_OF = {key: section for section, _, subs in SECTIONS for key, _, _ in subs}


async def case_shell(session: AsyncSession, case: Investigation, user: User, tab: str) -> dict:
    latest = await session.scalar(
        select(ScanRun).where(ScanRun.case_id == case.id).order_by(ScanRun.run_number.desc()).limit(1)
    )
    entity_count = await session.scalar(
        select(func.count())
        .select_from(Entity)
        .where(
            Entity.case_id == case.id,
            Entity.merged_into_id.is_(None),
            Entity.type != "web_mention",
            Entity.dismissed_flag.is_(False),
        )
    )
    web_count = await session.scalar(
        select(func.count())
        .select_from(Entity)
        .where(
            Entity.case_id == case.id,
            Entity.merged_into_id.is_(None),
            Entity.type == "web_mention",
            Entity.dismissed_flag.is_(False),
        )
    )
    pivot_count = await session.scalar(select(func.count()).select_from(PivotLog).where(PivotLog.case_id == case.id))
    review_count = await session.scalar(
        select(func.count())
        .select_from(Relation)
        .where(Relation.case_id == case.id, Relation.relation_type == POSSIBLE_SAME)
    )
    from app.services.visits import record_visit, since_last_visit

    previous = await record_visit(user, case.id)
    label = dict((k, v) for k, v, _ in TABS)[tab]
    path = f"/cases/{case.id}" + dict((k, p) for k, _, p in TABS)[tab]
    return {
        "seo": Seo(title=case.name if tab == "entities" else f"{label} · {case.name}", path=path),
        "user": user,
        "case": case,
        "tab": tab,
        "tabs": TABS,
        "sections": SECTIONS,
        "section": SECTION_OF.get(tab, tab),
        "latest_run": latest,
        "run": latest,
        "workers": worker_count(),
        "watch": watch_state(case),
        "auto_pivot": auto_pivot_enabled(case),
        "counts": {"entities": entity_count, "web": web_count, "pivots": pivot_count, "review": review_count},
        "since": await since_last_visit(session, case.id, previous),
    }
