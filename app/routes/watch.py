"""Timeline tab (scan-to-scan diff) and the watch-mode switch."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_access
from app.db import get_session
from app.models import ScanRun, User
from app.routes.shell import case_shell
from app.scheduler import set_watch, watch_state
from app.security import client_ip, current_user, verify_csrf
from app.services.cases import get_case_for_user
from app.services.timeline import default_pair, diff_runs, timeline_track
from app.web import render

router = APIRouter()


async def _timeline_context(request: Request, session: AsyncSession, case) -> dict:
    runs = list(
        (await session.scalars(select(ScanRun).where(ScanRun.case_id == case.id).order_by(ScanRun.run_number))).all()
    )
    by_number = {r.run_number: r for r in runs}
    run_a, run_b = default_pair(runs)
    q = request.query_params
    if q.get("a", "").isdigit() and int(q["a"]) in by_number:
        run_a = by_number[int(q["a"])]
    if q.get("b", "").isdigit() and int(q["b"]) in by_number:
        run_b = by_number[int(q["b"])]
    diff = None
    if run_a is not None and run_b is not None and run_a.id != run_b.id:
        diff = await diff_runs(session, case.id, run_a, run_b)
    track = await timeline_track(session, case.id, runs)
    peak = max((p.new for p in track), default=0)
    return {"case": case, "runs": runs, "run_a": run_a, "run_b": run_b, "diff": diff, "track": track, "peak": peak}


@router.get("/cases/{case_id}/tab/timeline")
async def timeline_tab(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    return render(request, "cases/_timeline_tab.html", await _timeline_context(request, session, case))


@router.get("/cases/{case_id}/timeline")
async def timeline_page(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    ctx = await case_shell(session, case, user, "timeline")
    return render(request, "cases/timeline.html", {**ctx, **await _timeline_context(request, session, case)})


@router.post("/cases/{case_id}/watch", dependencies=[Depends(verify_csrf)])
async def toggle_watch(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    if case.is_sample:
        raise HTTPException(status_code=400, detail="Sample cases can't be watched")
    enabled = not watch_state(case)["enabled"]
    set_watch(case, enabled=enabled)
    log_access(
        session, "watch_on" if enabled else "watch_off", user_id=user.id, case_id=case.id, ip=client_ip(request),
        frequency=watch_state(case)["frequency"],
    )  # fmt: skip
    await session.commit()
    return render(request, "partials/watch_toggle.html", {"case": case, "watch": watch_state(case)})
