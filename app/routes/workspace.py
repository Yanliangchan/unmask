"""Case workspace actions: the evidence drawer, notes, bulk decisions and saved views."""

from __future__ import annotations

import json
import re
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_access
from app.correlation.engine import lock_case, rescore_case
from app.db import get_session
from app.models import Entity, Note, SavedView, User
from app.security import client_ip, current_user, verify_csrf
from app.services.accuracy import DISMISS_REASONS
from app.services.cases import get_case_for_user
from app.services.entities import SHOW_MODES, entity_detail
from app.web import render

router = APIRouter()

BULK_ACTIONS = {"confirm", "unconfirm", "dismiss", "restore"}
VIEW_PARAMS = ("q", "type", "show", "tool")
_MENTION = re.compile(r"@([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
# Views every case has; saved views are added after these.
BUILT_IN_VIEWS = [
    ("Best findings", {"show": "best"}),
    ("Undecided", {"show": "undecided"}),
    ("Accounts to review", {"show": "undecided", "type": "account"}),
    ("Confirmed", {"show": "confirmed"}),
    ("Everything", {"show": "all"}),
]


def _changed(message: str, undo: str | None = None) -> Response:
    toast = {"message": message, **({"undo": undo} if undo else {})}
    return HTMLResponse("", headers={"HX-Trigger": json.dumps({"entities-changed": True, "toast": toast})})


async def _case_members(session: AsyncSession, case) -> dict[str, User]:
    ids = [case.owner_id, *(case.shared_with or [])]
    users = (await session.scalars(select(User).where(User.id.in_([i for i in ids if i])))).all()
    return {u.email.lower(): u for u in users}


# --- Evidence drawer ---------------------------------------------------------------------------


async def _drawer_context(session: AsyncSession, case, entity_id: uuid.UUID) -> dict:
    detail = await entity_detail(session, case.id, entity_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    notes = (await session.scalars(select(Note).where(Note.entity_id == entity_id).order_by(Note.created_at))).all()
    authors = {u.id: u for u in (await _case_members(session, case)).values()}
    return {
        "case": case,
        "d": detail,
        "entity": detail.entity,
        "notes": notes,
        "authors": authors,
        "reasons": DISMISS_REASONS,
        "members": sorted((await _case_members(session, case)).keys()),
    }


@router.get("/cases/{case_id}/entities/{entity_id}/drawer")
async def drawer(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    return render(request, "cases/_drawer.html", await _drawer_context(session, case, entity_id))


@router.post("/cases/{case_id}/entities/{entity_id}/notes", dependencies=[Depends(verify_csrf)])
async def add_note(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    body: str = Form(...),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    entity = await session.scalar(select(Entity).where(Entity.id == entity_id, Entity.case_id == case.id))
    body = body.strip()[:4000]
    if entity is None or not body:
        raise HTTPException(status_code=400, detail="Write something first")
    members = await _case_members(session, case)
    # Only people who can already see the case can be mentioned.
    mentioned = [members[m.lower()] for m in _MENTION.findall(body) if m.lower() in members]
    note = Note(case_id=case.id, entity_id=entity.id, author_id=user.id, body=body,
                mentions=sorted({str(u.id) for u in mentioned if u.id != user.id}))  # fmt: skip
    session.add(note)
    await session.flush()
    log_access(session, "add_note", user_id=user.id, case_id=case.id, ip=client_ip(request),
               entity_id=str(entity.id), mentions=len(note.mentions))  # fmt: skip
    from app.services.notifications import notify

    for uid in note.mentions:
        await notify(session, uuid.UUID(uid), case_id=case.id, kind="mention",
                     text=f"{user.email} mentioned you on a finding in {case.name}",
                     url=f"/cases/{case.id}#ent-{entity.id}")  # fmt: skip
    await session.commit()
    return render(request, "cases/_drawer.html", await _drawer_context(session, case, entity.id))


# --- Bulk decisions ------------------------------------------------------------------------------


@router.post("/cases/{case_id}/entities/bulk", dependencies=[Depends(verify_csrf)])
async def bulk(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    form = await request.form()
    action = str(form.get("action") or request.query_params.get("action") or "")
    # Ids arrive as repeated form fields, or comma-joined (the undo link, a single hidden input).
    raw = [str(v) for v in form.getlist("ids")] or [request.query_params.get("ids") or ""]
    raw_ids = [part for value in raw for part in value.split(",")]
    reason = str(form.get("reason") or "other")
    if action not in BULK_ACTIONS:
        raise HTTPException(status_code=400, detail="Unknown action")
    try:
        ids = [uuid.UUID(str(i)) for i in raw_ids if str(i).strip()]
    except ValueError:
        raise HTTPException(status_code=400, detail="Bad selection") from None
    if not ids:
        raise HTTPException(status_code=400, detail="Nothing selected")
    await lock_case(session, case.id)
    entities = (
        await session.scalars(
            select(Entity).where(Entity.case_id == case.id, Entity.id.in_(ids), Entity.is_seed.is_(False))
        )
    ).all()
    for e in entities:
        if action == "confirm":
            e.confirmed_flag, e.dismissed_flag, e.dismiss_reason = True, False, None
        elif action == "unconfirm":
            e.confirmed_flag = False
        elif action == "dismiss":
            e.dismissed_flag, e.confirmed_flag = True, False
            e.dismiss_reason = reason if reason in DISMISS_REASONS else "other"
        else:
            e.dismissed_flag, e.dismiss_reason = False, None
    log_access(session, f"bulk_{action}", user_id=user.id, case_id=case.id, ip=client_ip(request),
               count=len(entities))  # fmt: skip
    await rescore_case(session, case.id)
    await session.commit()
    inverse = {"confirm": "unconfirm", "unconfirm": "confirm", "dismiss": "restore", "restore": "dismiss"}[action]
    done = ",".join(str(e.id) for e in entities)
    verb = {"confirm": "Confirmed", "unconfirm": "Unconfirmed", "dismiss": "Marked not them", "restore": "Restored"}
    return _changed(
        f"{verb[action]}: {len(entities)} finding{'s' if len(entities) != 1 else ''}",
        undo=f"/cases/{case.id}/entities/bulk?action={inverse}&ids={done}",
    )


# --- Saved views --------------------------------------------------------------------------------


def clean_params(params: dict) -> dict:
    out = {k: str(v)[:200] for k, v in params.items() if k in VIEW_PARAMS and v}
    if out.get("show") and out["show"] not in SHOW_MODES:
        out.pop("show")
    return out


async def views_for(session: AsyncSession, case_id: uuid.UUID, user: User) -> list[SavedView]:
    return list(
        (
            await session.scalars(
                select(SavedView)
                .where(SavedView.case_id == case_id, SavedView.user_id == user.id)
                .order_by(SavedView.created_at)
            )
        ).all()
    )


def _views_menu(request: Request, case, views: list[SavedView]) -> Response:
    return render(request, "cases/_views_menu.html", {"case": case, "views": views, "built_in": BUILT_IN_VIEWS})


@router.post("/cases/{case_id}/views", dependencies=[Depends(verify_csrf)])
async def save_view(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    form = await request.form()
    name = str(form.get("name") or "").strip()[:80]
    if not name:
        raise HTTPException(status_code=400, detail="Give the view a name")
    params = clean_params({k: form.get(k) for k in VIEW_PARAMS})
    existing = await session.scalar(
        select(SavedView).where(SavedView.case_id == case.id, SavedView.user_id == user.id, SavedView.name == name)
    )
    if existing:
        existing.params = params
    else:
        session.add(SavedView(case_id=case.id, user_id=user.id, name=name, params=params))
    await session.commit()
    return _views_menu(request, case, await views_for(session, case.id, user))


@router.post("/cases/{case_id}/views/{view_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_view(
    request: Request,
    case_id: uuid.UUID,
    view_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    view = await session.scalar(
        select(SavedView).where(SavedView.id == view_id, SavedView.case_id == case.id, SavedView.user_id == user.id)
    )
    if view is not None:
        await session.delete(view)
        await session.commit()
    return _views_menu(request, case, await views_for(session, case.id, user))
