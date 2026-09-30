"""Page snapshots, data exports and read-only share links."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from starlette.background import BackgroundTask

from app import safefetch
from app.audit import log_access
from app.db import get_session
from app.models import Entity, Investigation, ShareLink, Snapshot, User
from app.routes.settings import _back, _is_owner, settings_context
from app.security import client_ip, current_user, verify_csrf
from app.services import exports
from app.services.cases import get_case_for_user
from app.services.evidence import (
    capture,
    create_share_link,
    decode,
    page_text,
    resolve_share_link,
    snapshot_body,
    snapshot_intact,
)
from app.services.report import AssessmentRequired, assessment_ready, build_report
from app.web import Seo, render

router = APIRouter()


# --- Snapshots ---------------------------------------------------------------------------------


@router.post("/cases/{case_id}/entities/{entity_id}/snapshot", dependencies=[Depends(verify_csrf)])
async def take_snapshot(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    entity = await session.scalar(select(Entity).where(Entity.id == entity_id, Entity.case_id == case.id))
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    try:
        snap = await capture(session, case, entity, user)
    except safefetch.BlockedURL as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except Exception as exc:  # network errors: tell the analyst, don't 500
        raise HTTPException(status_code=502, detail=f"The page couldn't be loaded ({exc.__class__.__name__})") from None
    log_access(session, "capture_snapshot", user_id=user.id, case_id=case.id, ip=client_ip(request),
               entity_id=str(entity.id), sha256=snap.sha256)  # fmt: skip
    await session.commit()
    toast = {"message": f"Page saved · SHA-256 {snap.sha256[:12]}…"}
    return HTMLResponse("", headers={"HX-Trigger": json.dumps({"entities-changed": True, "toast": toast})})


async def _snapshot(session: AsyncSession, case: Investigation, snapshot_id: uuid.UUID) -> Snapshot:
    snap = await session.scalar(select(Snapshot).where(Snapshot.id == snapshot_id, Snapshot.case_id == case.id))
    if snap is None:
        raise HTTPException(status_code=404, detail="Snapshot not found")
    return snap


@router.get("/cases/{case_id}/snapshots/{snapshot_id}")
async def view_snapshot(
    request: Request,
    case_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    snap = await _snapshot(session, case, snapshot_id)
    by = await session.get(User, snap.captured_by) if snap.captured_by else None
    # The captured page is shown as text, never rendered: it's untrusted markup.
    _, text = page_text(decode(snap))
    return render(
        request,
        "cases/snapshot.html",
        {
            "seo": Seo(title=f"Snapshot · {case.name}", path=f"/cases/{case.id}/snapshots/{snap.id}"),
            "user": user,
            "case": case,
            "s": snap,
            "by": by,
            "text": text[:200_000],
            "intact": snapshot_intact(snap),
        },
    )


@router.get("/cases/{case_id}/snapshots/{snapshot_id}/raw")
async def download_snapshot(
    request: Request,
    case_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    snap = await _snapshot(session, case, snapshot_id)
    log_access(session, "download_snapshot", user_id=user.id, case_id=case.id, ip=client_ip(request),
               sha256=snap.sha256)  # fmt: skip
    await session.commit()
    # Always a download, never rendered in the app's origin.
    return Response(
        snapshot_body(snap),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="snapshot-{snap.sha256[:16]}.html"',
            "Content-Security-Policy": "sandbox",
            "X-Content-Type-Options": "nosniff",
        },
    )


# --- Exports -----------------------------------------------------------------------------------

FORMATS = {"csv": "text/csv; charset=utf-8", "json": "application/json", "stix": "application/stix+json;version=2.1"}


@router.get("/cases/{case_id}/export.{fmt}")
async def export_case(
    request: Request,
    case_id: uuid.UUID,
    fmt: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    if fmt not in FORMATS:
        raise HTTPException(status_code=404)
    case = await get_case_for_user(session, case_id, user)
    scope = request.query_params.get("scope", "visible")
    scope = scope if scope in exports.SCOPES else "visible"
    if fmt == "csv":
        body = "﻿" + await exports.export_csv(session, case, scope)  # BOM so Excel reads UTF-8
        ext = "csv"
    elif fmt == "json":
        body, ext = json.dumps(await exports.export_json(session, case, scope), indent=2, ensure_ascii=False), "json"
    else:
        body, ext = (
            json.dumps(await exports.export_stix(session, case, scope), indent=2, ensure_ascii=False),
            "stix.json",
        )
    log_access(session, "export_data", user_id=user.id, case_id=case.id, ip=client_ip(request), format=fmt, scope=scope)
    await session.commit()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    data = body.encode("utf-8")
    del body  # keep one copy of a large export, not two
    from app.memory import trim

    return Response(
        data,
        media_type=FORMATS[fmt],
        headers={"Content-Disposition": f'attachment; filename="unmask-case-{case.id}-{stamp}.{ext}"'},
        background=BackgroundTask(trim),  # once sent, hand the buffers back
    )


# --- Share links -------------------------------------------------------------------------------


@router.post("/cases/{case_id}/share-links", dependencies=[Depends(verify_csrf)])
async def new_share_link(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    if not _is_owner(case, user):
        return _back(case, error="not_owner")
    if not assessment_ready(case):
        return _back(case, error="assessment")
    form = await request.form()
    try:
        days = int(str(form.get("days") or 7))
    except ValueError:
        days = 7
    link, token = await create_share_link(session, case, user, days=days, label=str(form.get("label") or ""))
    log_access(session, "create_share_link", user_id=user.id, case_id=case.id, ip=client_ip(request),
               link_id=str(link.id), expires_at=link.expires_at.isoformat())  # fmt: skip
    await session.commit()
    url = str(request.base_url).rstrip("/") + f"/s/{token}"
    return render(request, "cases/settings.html", await settings_context(request, session, case, user, new_link=url))


@router.post("/cases/{case_id}/share-links/{link_id}/revoke", dependencies=[Depends(verify_csrf)])
async def revoke_share_link(
    request: Request,
    case_id: uuid.UUID,
    link_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    if not _is_owner(case, user):
        return _back(case, error="not_owner")
    link = await session.scalar(select(ShareLink).where(ShareLink.id == link_id, ShareLink.case_id == case.id))
    if link is not None and link.revoked_at is None:
        link.revoked_at = datetime.now(UTC)
        log_access(session, "revoke_share_link", user_id=user.id, case_id=case.id, ip=client_ip(request),
                   link_id=str(link.id))  # fmt: skip
        await session.commit()
    return _back(case, saved="link_revoked")


NO_INDEX = {"X-Robots-Tag": "noindex, nofollow, noarchive", "Cache-Control": "no-store"}


@router.get("/s/{token}")
async def shared_report(request: Request, token: str, session: AsyncSession = Depends(get_session)):
    link = await resolve_share_link(session, token)
    case = (
        await session.scalar(
            select(Investigation)
            .where(Investigation.id == link.case_id)
            .options(selectinload(Investigation.targets), selectinload(Investigation.scan_runs))
        )
        if link
        else None
    )
    if link is None or case is None:
        return render(request, "shared_gone.html", {"seo": Seo(title="Link unavailable")},
                      status_code=404, headers=NO_INDEX)  # fmt: skip
    owner = await session.get(User, case.owner_id) if case.owner_id else None
    try:
        report = await build_report(session, case, owner or User(email="the case owner"))
    except AssessmentRequired:
        return render(request, "shared_gone.html", {"seo": Seo(title="Link unavailable")},
                      status_code=404, headers=NO_INDEX)  # fmt: skip
    link.views += 1
    link.last_viewed_at = datetime.now(UTC)
    log_access(session, "view_share_link", user_id=None, case_id=case.id, ip=client_ip(request), link_id=str(link.id))
    await session.commit()
    return render(
        request,
        "cases/report.html",
        {"seo": Seo(title=f"Report · {case.name}"), "r": report, "shared": link},
        headers=NO_INDEX,
    )
