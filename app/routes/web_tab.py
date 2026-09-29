"""The Web tab: search results as a reading list, and findings the analyst adds by hand."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto
from app.adapters.registry import get_adapter
from app.audit import log_access
from app.correlation.engine import lock_case, rescore_case
from app.db import get_session
from app.models import Entity, User
from app.routes.shell import case_shell
from app.search.providers import active_provider, setup_hint
from app.security import client_ip, current_user, verify_csrf
from app.services.cases import get_case_for_user
from app.web import render

router = APIRouter()

# What an analyst can add by hand, with the label shown in the form.
ADDABLE = [
    ("web_mention", "Web page"),
    ("account", "Profile / account"),
    ("email", "Email"),
    ("username", "Username"),
    ("name", "Name"),
    ("phone", "Phone"),
    ("domain", "Domain"),
]
WEB_SHOW = ("results", "kept", "dismissed")


async def _web_rows(session: AsyncSession, case_id: uuid.UUID, show: str) -> tuple[list[Entity], dict[str, int]]:
    mentions = [
        e
        for e in (
            await session.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "web_mention"))
        ).all()
        if e.merged_into_id is None
    ]
    counts = {
        "results": sum(1 for e in mentions if not e.dismissed_flag),
        "kept": sum(1 for e in mentions if e.confirmed_flag and not e.dismissed_flag),
        "dismissed": sum(1 for e in mentions if e.dismissed_flag),
    }
    if show == "kept":
        rows = [e for e in mentions if e.confirmed_flag and not e.dismissed_flag]
    elif show == "dismissed":
        rows = [e for e in mentions if e.dismissed_flag]
    else:
        rows = [e for e in mentions if not e.dismissed_flag]
    # Kept first, then pages more searches led to, then by search rank.
    rows.sort(
        key=lambda e: (
            not e.confirmed_flag,
            -len((e.attributes or {}).get("found_by") or [1]),
            (e.attributes or {}).get("rank") or 99,
            -e.confidence,
        )
    )
    return rows, counts


@router.get("/cases/{case_id}/web")
async def web_tab(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    provider = active_provider()
    adapter = get_adapter("websearch")
    return render(
        request,
        "cases/web.html",
        {
            **await case_shell(session, case, user, "web"),
            "provider": provider.label if provider else None,
            "setup_hint": setup_hint(),
            "search_available": adapter is not None and provider is not None,
            "addable": ADDABLE,
            "added": request.query_params.get("added"),
        },
    )


@router.get("/cases/{case_id}/web/results")
async def web_results(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    show = request.query_params.get("show") if request.query_params.get("show") in WEB_SHOW else "results"
    rows, counts = await _web_rows(session, case.id, show)
    return render(request, "cases/_web_results.html", {"case": case, "rows": rows, "counts": counts, "show": show})


@router.post("/cases/{case_id}/findings", dependencies=[Depends(verify_csrf)])
async def add_finding(
    request: Request,
    case_id: uuid.UUID,
    type: str = Form(...),  # noqa: A002 — the form field is called "type"
    value: str = Form(...),
    note: str = Form(""),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """Record something the analyst found outside the tools (their own search, a document...)."""
    case = await get_case_for_user(session, case_id, user)
    value = value.strip()[:2000]
    if type not in dict(ADDABLE) or not value:
        raise HTTPException(status_code=400, detail="Choose a type and enter a value")
    await lock_case(session, case.id)
    digest = crypto.digest(type, value)
    entity = await session.scalar(
        select(Entity).where(Entity.case_id == case.id, Entity.type == type, Entity.value_digest == digest).limit(1)
    )
    attrs = {"origin": f"added by {user.email}"}
    if value.startswith(("http://", "https://")):
        attrs["url"] = value
    if note.strip():
        attrs["note"] = note.strip()[:1000]
    now = datetime.now(UTC)
    if entity is None:
        entity = Entity(
            case_id=case.id,
            type=type,
            value=value,
            value_digest=digest,
            attributes=attrs,
            source_tool="analyst",
            confidence=1.0,
            field_confidence={"prior": 0.9},
            source_reliability="B",
            confirmed_flag=True,
            first_seen=now,
            last_verified=now,
        )
        session.add(entity)
    else:
        entity.attributes = {**(entity.attributes or {}), **attrs}
        entity.confirmed_flag, entity.dismissed_flag = True, False
    await session.flush()
    log_access(session, "add_finding", user_id=user.id, case_id=case.id, ip=client_ip(request),
               entity_id=str(entity.id), entity_type=type)  # fmt: skip
    await rescore_case(session, case.id)
    await session.commit()
    back = "/web" if request.query_params.get("from") == "web" else ""
    return RedirectResponse(f"/cases/{case.id}{back}?added={type}", status_code=303)
