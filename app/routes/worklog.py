"""The case working log: entries, pinned findings and links, and drafting the assessment from them."""

from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_access
from app.db import get_session
from app.models import Entity, Note, Relation, User
from app.routes.shell import case_shell
from app.security import client_ip, current_user, verify_csrf
from app.services.cases import get_case_for_user
from app.services.worklog import MAX_BODY, MAX_WHY, existing_pin, worklog
from app.web import render

router = APIRouter()


@router.get("/cases/{case_id}/log")
async def log_page(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    ctx = await case_shell(session, case, user, "log")
    return render(request, "cases/log.html", {**ctx, "log": await worklog(session, case.id)})


@router.post("/cases/{case_id}/log", dependencies=[Depends(verify_csrf)])
async def add_entry(
    request: Request,
    case_id: uuid.UUID,
    body: str = Form(""),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    body = body.strip()[:MAX_BODY]
    if not body:
        return RedirectResponse(f"/cases/{case.id}/log", status_code=303)
    note = Note(case_id=case.id, kind="log", author_id=user.id, body=body)
    session.add(note)
    await session.flush()
    log_access(session, "log_entry", user_id=user.id, case_id=case.id, ip=client_ip(request), length=len(body))
    await session.commit()
    return RedirectResponse(f"/cases/{case.id}/log#entry-{note.id}", status_code=303)


async def _own_note(session: AsyncSession, case, note_id: uuid.UUID, user: User, kinds: tuple[str, ...]) -> Note:
    note = await session.scalar(select(Note).where(Note.id == note_id, Note.case_id == case.id, Note.kind.in_(kinds)))
    if note is None:
        raise HTTPException(status_code=404, detail="Not found")
    if note.author_id != user.id and case.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Only its author or the case owner can remove this")
    return note


@router.post("/cases/{case_id}/log/{note_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_entry(
    request: Request,
    case_id: uuid.UUID,
    note_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    note = await _own_note(session, case, note_id, user, ("log", "pin"))
    action = "unpin" if note.kind == "pin" else "delete_log_entry"
    await session.delete(note)
    log_access(session, action, user_id=user.id, case_id=case.id, ip=client_ip(request))
    await session.commit()
    return RedirectResponse(f"/cases/{case.id}/log", status_code=303)


def _pinned(request: Request, case_id: uuid.UUID, message: str):
    if request.headers.get("HX-Request"):
        return HTMLResponse("", headers={"HX-Trigger": json.dumps({"toast": {"message": message}})})
    return RedirectResponse(f"/cases/{case_id}/log", status_code=303)


@router.post("/cases/{case_id}/entities/{entity_id}/pin", dependencies=[Depends(verify_csrf)])
async def pin_finding(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    why: str = Form(""),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    entity = await session.scalar(select(Entity).where(Entity.id == entity_id, Entity.case_id == case.id))
    if entity is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    if await existing_pin(session, case.id, entity_id=entity.id):
        return _pinned(request, case.id, "Already pinned to the working log.")
    session.add(Note(case_id=case.id, kind="pin", entity_id=entity.id, author_id=user.id, body=why.strip()[:MAX_WHY]))
    log_access(session, "pin", user_id=user.id, case_id=case.id, ip=client_ip(request), entity_id=str(entity.id))
    await session.commit()
    return _pinned(request, case.id, "Pinned to the working log.")


@router.post("/cases/{case_id}/links/{relation_id}/pin", dependencies=[Depends(verify_csrf)])
async def pin_link(
    request: Request,
    case_id: uuid.UUID,
    relation_id: uuid.UUID,
    why: str = Form(""),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    rel = await session.scalar(select(Relation).where(Relation.id == relation_id, Relation.case_id == case.id))
    if rel is None:
        raise HTTPException(status_code=404, detail="Link not found")
    if await existing_pin(session, case.id, relation_id=rel.id):
        return _pinned(request, case.id, "Already pinned to the working log.")
    session.add(Note(case_id=case.id, kind="pin", relation_id=rel.id, author_id=user.id, body=why.strip()[:MAX_WHY]))
    log_access(session, "pin", user_id=user.id, case_id=case.id, ip=client_ip(request), relation_id=str(rel.id))
    await session.commit()
    return _pinned(request, case.id, "Link pinned to the working log.")
