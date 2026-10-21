"""Pivot Log screen and the per-case auto-pivot switch."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.registry import get_adapter
from app.audit import log_access
from app.db import get_session
from app.models import Entity, PivotLog, ScanRun, User
from app.pivots.engine import auto_pivot_enabled, retry_pivots
from app.pivots.rules import rule_from_text
from app.routes.shell import case_shell
from app.security import client_ip, current_user, verify_csrf
from app.services.cases import get_case_for_user, quota_problem, require_owner
from app.web import render

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
    value: str | None = None  # expected value it was ranked by
    retried: str | None = None  # why it had been skipped, when an analyst retried it


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
                value=note.removeprefix("value ") if note.startswith("value ") else None,
                retried=note.removeprefix("retried by analyst (").rstrip(")") if note.startswith("retried") else None,
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
    ctx = await case_shell(session, case, user, "pivots")
    q = request.query_params
    return render(request, "cases/pivots.html", {
        **ctx, "rows": await pivot_rows(session, case.id),
        "retried": q.get("retried"), "refused": q.get("refused"), "why": q.get("why"),
    })  # fmt: skip


async def _retry(request: Request, session: AsyncSession, user: User, case_id: uuid.UUID, pivot_id=None):
    from app.services.scans import dispatch

    case = await get_case_for_user(session, case_id, user)
    if case.is_sample:
        raise HTTPException(status_code=400, detail="Sample cases use made-up data and can't be scanned")
    where = [PivotLog.case_id == case.id, PivotLog.scan_run_id.is_(None)]
    if pivot_id is not None:
        where.append(PivotLog.id == pivot_id)
    rows = (await session.scalars(select(PivotLog).where(*where).order_by(PivotLog.created_at))).all()
    if pivot_id is not None and not rows:
        raise HTTPException(status_code=404, detail="No such skipped pivot")
    back = f"/cases/{case.id}/pivots"
    if (problem := await quota_problem(session, user, new_scans=1)) is not None:
        await session.commit()  # the refusal is audited
        return RedirectResponse(f"{back}?{urlencode({'why': problem})}", status_code=303)
    run, refused = await retry_pivots(session, case, list(rows))
    if run is not None:
        log_access(session, "retry_pivots", user_id=user.id, case_id=case.id, ip=client_ip(request),
                   run_number=run.run_number, pivots=run.jobs_total)  # fmt: skip
    await session.commit()
    if run is not None:
        await dispatch(run.id, run.triggered_by)
    query = {"retried": run.jobs_total if run else 0, "refused": len(refused)}
    if pivot_id is not None and refused:
        query["why"] = next(iter(refused.values()))
    return RedirectResponse(f"{back}?{urlencode(query)}", status_code=303)


@router.post("/cases/{case_id}/pivots/retry-skipped", dependencies=[Depends(verify_csrf)])
async def retry_all_skipped(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """Retry every skipped pivot that can run now, as one follow-up scan."""
    return await _retry(request, session, user, case_id)


@router.post("/cases/{case_id}/pivots/{pivot_id}/retry", dependencies=[Depends(verify_csrf)])
async def retry_one(
    request: Request,
    case_id: uuid.UUID,
    pivot_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    return await _retry(request, session, user, case_id, pivot_id)


@router.post("/cases/{case_id}/auto-pivot", dependencies=[Depends(verify_csrf)])
async def toggle_auto_pivot(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    require_owner(case, user)
    enabled = not auto_pivot_enabled(case)
    case.watch_config = {**(case.watch_config or {}), "auto_pivot": enabled}
    log_access(
        session, "auto_pivot_on" if enabled else "auto_pivot_off", user_id=user.id, case_id=case.id,
        ip=client_ip(request),
    )  # fmt: skip
    await session.commit()
    return render(request, "partials/auto_pivot.html", {"case": case, "auto_pivot": enabled})
