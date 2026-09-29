"""The review queue: one finding at a time, next to what is known about the subject.

Answers go through the same Confirm / Not them endpoints as the table, so
every decision is audited and feeds per-site accuracy.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import Entity, Target, User
from app.routes.shell import case_shell
from app.security import current_user
from app.services.accuracy import DISMISS_REASONS
from app.services.cases import get_case_for_user
from app.services.entities import entity_detail, hidden_reason
from app.web import render

router = APIRouter()


async def review_queue(session: AsyncSession, case_id: uuid.UUID, *, include_hidden: bool = False) -> list[Entity]:
    """Undecided findings, strongest first. Web results have their own tab."""
    entities = (await session.scalars(select(Entity).where(Entity.case_id == case_id))).all()
    queue = [
        e
        for e in entities
        if e.merged_into_id is None
        and not e.is_seed
        and not e.confirmed_flag
        and not e.dismissed_flag
        and e.type != "web_mention"
        and (include_hidden or hidden_reason(e) is None)
    ]
    queue.sort(key=lambda e: (-e.confidence, e.first_seen))
    return queue


@router.get("/cases/{case_id}/review")
async def review_page(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    return render(
        request,
        "cases/review.html",
        {**await case_shell(session, case, user, "entities"), "all": request.query_params.get("all") == "1"},
    )


@router.get("/cases/{case_id}/review/next")
async def review_next(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    include_hidden = request.query_params.get("all") == "1"
    skipped = {s for s in (request.query_params.get("skip") or "").split(",") if s}
    queue = await review_queue(session, case.id, include_hidden=include_hidden)
    remaining = [e for e in queue if str(e.id) not in skipped]
    hidden_left = 0 if include_hidden else len(await review_queue(session, case.id, include_hidden=True)) - len(queue)
    ctx = {
        "case": case,
        "remaining": len(remaining),
        "skipped": len(queue) - len(remaining),
        "hidden_left": hidden_left,
        "include_hidden": include_hidden,
        "reasons": DISMISS_REASONS,
    }
    if remaining:
        entity = remaining[0]
        targets = (await session.scalars(select(Target).where(Target.case_id == case.id))).all()
        ctx.update(entity=entity, d=await entity_detail(session, case.id, entity.id), targets=targets)
    return render(request, "cases/_review_card.html", ctx)
