"""Analyst controls over correlation: merge, split, review suggestions, re-run.

Every decision here is a human override: it is audited in access_log, stored
as an analyst relation the engine will never undo, and rescored immediately.
"""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_access
from app.correlation.embeddings import get_embedder
from app.correlation.engine import (
    POSSIBLE_SAME,
    correlate_and_commit,
    dismiss_suggestion,
    lock_case,
    merge_entities,
    rescore_case,
    split_entity,
)
from app.db import get_session
from app.jobs import enqueue_correlation, uses_rq
from app.models import Entity, Relation, User
from app.security import client_ip, current_user, verify_csrf
from app.services.accuracy import DISMISS_REASONS
from app.services.cases import get_case_for_user
from app.services.entities import list_suggestions, merge_candidates
from app.web import render

router = APIRouter()


def _changed(message: str, undo: str | None = None) -> Response:
    """Empty response that tells the page to refresh the entity views.

    ``undo`` is a POST endpoint that reverses the action; the toast offers it
    as a button instead of asking "are you sure?" up front.
    """
    toast = {"message": message, **({"undo": undo} if undo else {})}
    # ensure_ascii: header values must be latin-1; names can be any script.
    trigger = json.dumps({"entities-changed": True, "toast": toast}, ensure_ascii=True)
    return HTMLResponse("", headers={"HX-Trigger": trigger})


async def _entity(session: AsyncSession, case_id: uuid.UUID, entity_id: uuid.UUID) -> Entity:
    entity = await session.scalar(select(Entity).where(Entity.id == entity_id, Entity.case_id == case_id))
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    return entity


@router.get("/cases/{case_id}/suggestions")
async def suggestions_partial(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    embedder, reason = get_embedder()
    return render(
        request,
        "cases/_suggestions.html",
        {
            "case": case,
            "suggestions": await list_suggestions(session, case.id),
            "pass2": embedder.name if embedder else None,
            "pass2_reason": reason,
        },
    )


@router.get("/cases/{case_id}/entities/{entity_id}/merge")
async def merge_picker(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    entity = await _entity(session, case.id, entity_id)
    return render(
        request,
        "cases/_merge_picker.html",
        {"case": case, "entity": entity, "candidates": await merge_candidates(session, entity)},
    )


@router.post("/cases/{case_id}/entities/{entity_id}/merge", dependencies=[Depends(verify_csrf)])
async def merge(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    other_id: uuid.UUID = Form(...),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    await lock_case(session, case.id)
    a, b = await _entity(session, case.id, entity_id), await _entity(session, case.id, other_id)
    if a.merged_into_id or b.merged_into_id:
        raise HTTPException(status_code=409, detail="One of these entities is already merged")
    try:
        winner = await merge_entities(
            session, a, b, created_by=f"analyst:{user.id}", explanation=f"merged by analyst {user.email}"
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    log_access(
        session, "merge_entities", user_id=user.id, case_id=case.id, ip=client_ip(request),
        winner=str(winner.id), merged=[str(a.id), str(b.id)],
    )  # fmt: skip
    await rescore_case(session, case.id)
    await session.commit()
    loser = b if winner.id == a.id else a
    return _changed("Merged", undo=f"/cases/{case.id}/entities/{loser.id}/split")


@router.post("/cases/{case_id}/entities/{entity_id}/split", dependencies=[Depends(verify_csrf)])
async def split(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    await lock_case(session, case.id)
    member = await _entity(session, case.id, entity_id)
    winner_id = member.merged_into_id
    try:
        await split_entity(
            session, member, created_by=f"analyst:{user.id}", explanation=f"split by analyst {user.email}"
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    log_access(
        session, "split_entity", user_id=user.id, case_id=case.id, ip=client_ip(request),
        entity=str(member.id), was_merged_into=str(winner_id),
    )  # fmt: skip
    await rescore_case(session, case.id)
    await session.commit()
    return _changed("Entity split out; it will not be merged again automatically")


@router.post("/cases/{case_id}/entities/{entity_id}/dismiss", dependencies=[Depends(verify_csrf)])
async def dismiss_entity(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """ "Not them": hide a finding from views, graph and reports, keeping it on record."""
    case = await get_case_for_user(session, case_id, user)
    entity = await _entity(session, case.id, entity_id)
    if entity.is_seed:
        raise HTTPException(status_code=400, detail="A target can't be ruled out; edit the case instead")
    reason = str((await request.form()).get("reason") or "other")
    entity.dismissed_flag = True
    entity.confirmed_flag = False
    entity.dismiss_reason = reason if reason in DISMISS_REASONS else "other"
    log_access(session, "dismiss_entity", user_id=user.id, case_id=case.id, ip=client_ip(request),
               entity_id=str(entity.id), reason=entity.dismiss_reason)  # fmt: skip
    await session.commit()
    what = "Marked not relevant" if entity.type == "web_mention" else "Marked as not them"
    return _changed(f"{what}: {entity.value[:60]}", undo=f"/cases/{case.id}/entities/{entity.id}/restore")


@router.post("/cases/{case_id}/entities/{entity_id}/restore", dependencies=[Depends(verify_csrf)])
async def restore_entity(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    entity = await _entity(session, case.id, entity_id)
    entity.dismissed_flag = False
    entity.dismiss_reason = None
    log_access(session, "restore_entity", user_id=user.id, case_id=case.id, ip=client_ip(request),
               entity_id=str(entity.id))  # fmt: skip
    await session.commit()
    return _changed(f"Restored: {entity.value[:60]}")


async def _suggestion(session: AsyncSession, case_id: uuid.UUID, relation_id: uuid.UUID) -> Relation:
    rel = await session.scalar(
        select(Relation).where(
            Relation.id == relation_id, Relation.case_id == case_id, Relation.relation_type == POSSIBLE_SAME
        )
    )
    if rel is None:
        raise HTTPException(status_code=404, detail="Suggestion not found (already reviewed?)")
    return rel


@router.post("/cases/{case_id}/suggestions/{relation_id}/accept", dependencies=[Depends(verify_csrf)])
async def accept_suggestion(
    request: Request,
    case_id: uuid.UUID,
    relation_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    await lock_case(session, case.id)
    rel = await _suggestion(session, case.id, relation_id)
    a, b = await _entity(session, case.id, rel.entity_a_id), await _entity(session, case.id, rel.entity_b_id)
    reason = rel.match_explanation
    try:
        winner = await merge_entities(
            session, a, b, created_by=f"analyst:{user.id}",
            explanation=f"suggestion accepted by analyst {user.email}: {reason}",
        )  # fmt: skip
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    log_access(
        session, "accept_suggestion", user_id=user.id, case_id=case.id, ip=client_ip(request),
        winner=str(winner.id), merged=[str(a.id), str(b.id)],
    )  # fmt: skip
    await rescore_case(session, case.id)
    await session.commit()
    return _changed("Suggestion accepted: entities merged")


@router.post("/cases/{case_id}/suggestions/{relation_id}/dismiss", dependencies=[Depends(verify_csrf)])
async def dismiss(
    request: Request,
    case_id: uuid.UUID,
    relation_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    await lock_case(session, case.id)
    rel = await _suggestion(session, case.id, relation_id)
    await dismiss_suggestion(session, rel, created_by=f"analyst:{user.id}")
    log_access(
        session, "dismiss_suggestion", user_id=user.id, case_id=case.id, ip=client_ip(request),
        pair=[str(rel.entity_a_id), str(rel.entity_b_id)],
    )  # fmt: skip
    await session.commit()
    return _changed("Suggestion dismissed; this pair will not be suggested again")


@router.post("/cases/{case_id}/correlate", dependencies=[Depends(verify_csrf)])
async def correlate(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    log_access(session, "run_correlation", user_id=user.id, case_id=case.id, ip=client_ip(request))
    await session.commit()
    if uses_rq():
        enqueue_correlation(case.id)
        return _changed("Correlation queued")
    result = await correlate_and_commit(session, case.id)
    return _changed(f"Correlation finished: {result.summary()}")
