"""Pivot Log screen and the per-case auto-pivot switch."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.registry import get_adapter
from app.audit import log_access
from app.db import get_session
from app.models import Entity, PivotLog, ScanRun, User
from app.pivots.engine import auto_pivot_enabled
from app.pivots.rules import rule_from_text
from app.security import client_ip, current_user, verify_csrf
from app.services.cases import get_case_for_user
from app.web import Seo, render

router = APIRouter()


@dataclass
class PivotRow:
    row: PivotLog
    entity: Entity | None
    source_run: int | None  # run whose finding triggered the pivot
    pivot_run: ScanRun | None  # run the pivot executed in
    tool_label: str
    rule_label: str
    skipped_reason: str | None


async def pivot_rows(session: AsyncSession, case_id: uuid.UUID) -> list[PivotRow]:
    rows = (
        await session.scalars(select(PivotLog).where(PivotLog.case_id == case_id).order_by(PivotLog.created_at.desc()))
    ).all()
    entity_ids = {r.triggering_entity_id for r in rows if r.triggering_entity_id}
    entities = {e.id: e for e in (await session.scalars(select(Entity).where(Entity.id.in_(entity_ids)))).all()}
    runs = {r.id: r for r in (await session.scalars(select(ScanRun).where(ScanRun.case_id == case_id))).all()}
    out = []
    for r in rows:
        entity = entities.get(r.triggering_entity_id)
        rule = rule_from_text(r.rule_matched)
        _, _, note = r.rule_matched.partition(" — ")
        adapter = get_adapter(r.triggered_tool)
        source = runs.get(entity.scan_run_id) if entity and entity.scan_run_id else None
        out.append(
            PivotRow(
                row=r,
                entity=entity,
                source_run=source.run_number if source else None,
                pivot_run=runs.get(r.scan_run_id) if r.scan_run_id else None,
                tool_label=adapter.label if adapter else r.triggered_tool,
                rule_label=rule.label if rule else r.rule_matched,
                skipped_reason=note.removeprefix("skipped: ") if note.startswith("skipped:") else None,
            )
        )
    return out


@router.get("/cases/{case_id}/pivots")
async def pivot_log(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    log_access(session, "view_pivot_log", user_id=user.id, case_id=case.id, ip=client_ip(request))
    await session.commit()
    return render(
        request,
        "cases/pivots.html",
        {
            "seo": Seo(title=f"Pivot log · {case.name}", path=f"/cases/{case.id}/pivots"),
            "user": user,
            "case": case,
            "rows": await pivot_rows(session, case.id),
            "auto_pivot": auto_pivot_enabled(case),
        },
    )


@router.post("/cases/{case_id}/auto-pivot", dependencies=[Depends(verify_csrf)])
async def toggle_auto_pivot(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    enabled = not auto_pivot_enabled(case)
    case.watch_config = {**(case.watch_config or {}), "auto_pivot": enabled}
    log_access(
        session, "auto_pivot_on" if enabled else "auto_pivot_off", user_id=user.id, case_id=case.id,
        ip=client_ip(request),
    )  # fmt: skip
    await session.commit()
    return render(request, "partials/auto_pivot.html", {"case": case, "auto_pivot": enabled})
