"""Page snapshots, data exports and read-only share links."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload, undefer
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
    snap = await session.scalar(
        select(Snapshot)
        .where(Snapshot.id == snapshot_id, Snapshot.case_id == case.id)
        .options(undefer(Snapshot.body_b64))
    )
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
    if not assessment_ready(case):
        # Same rule as reports: data leaves the platform only with a written conclusion beside it.
        return RedirectResponse(f"/cases/{case.id}/deliver?error=assessment#report", status_code=303)
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


@router.get("/cases/{case_id}/bundle.zip")
async def evidence_bundle(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    from app.services.bundle import build_bundle

    case = await get_case_for_user(session, case_id, user)
    if not assessment_ready(case):
        return RedirectResponse(f"/cases/{case.id}/deliver?error=assessment#report", status_code=303)
    log_access(session, "export_bundle", user_id=user.id, case_id=case.id, ip=client_ip(request))
    await session.commit()
    data, digest = await build_bundle(session, case, user)
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M")
    return Response(data, media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="unmask-evidence-{case.id}-{stamp}.zip"',
        "X-Manifest-SHA256": digest,
    })  # fmt: skip


@router.get("/cases/{case_id}/download")
async def download(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """The report in one or more formats (?f=pdf&f=docx...). One format is sent as is; several come as a ZIP."""
    from anyio import to_thread

    from app.services import exporters
    from app.services.bundle import build_bundle
    from app.services.document import DETAILS, SCOPES, build_document

    case = await get_case_for_user(session, case_id, user)
    if not assessment_ready(case):
        return RedirectResponse(f"/cases/{case.id}/deliver?error=assessment#report", status_code=303)
    q = request.query_params
    formats = [f for f in dict.fromkeys(q.getlist("f")) if f in exporters.FORMATS]
    if not formats:
        return RedirectResponse(f"/cases/{case.id}/deliver?error=formats#export", status_code=303)
    scope = q.get("scope") if q.get("scope") in SCOPES else "visible"
    detail = q.get("detail") if q.get("detail") in DETAILS else "full"
    log_access(session, "export_report", user_id=user.id, case_id=case.id, ip=client_ip(request),
               formats=formats, scope=scope, detail=detail)  # fmt: skip
    await session.commit()

    doc = await build_document(session, case, user, scope, detail)
    # Raw data is always complete, whatever the presentation formats leave out.
    raw_doc = doc if detail == "full" else await build_document(session, case, user, scope, "full")
    base = f"{exporters.slug(case.name)}-{'brief' if detail == 'brief' else 'report'}-{doc.ref}"
    files: dict[str, bytes] = {}
    for f in formats:
        _, _, ext = exporters.FORMATS[f]
        if f == "pdf":
            body = await to_thread.run_sync(exporters.render_pdf, doc)
        elif f == "docx":
            body = await to_thread.run_sync(exporters.render_docx, doc)
        elif f == "html":
            body = exporters.render_html(doc).encode()
        elif f == "md":
            body = exporters.render_markdown(doc).encode()
        elif f == "txt":
            body = exporters.render_text(raw_doc).encode()
        else:
            body, _digest = await build_bundle(session, case, user)
            files[f"{exporters.slug(case.name)}-evidence-{doc.ref}.zip"] = body
            continue
        files[f"{base}.{ext}" if f != "txt" else f"{exporters.slug(case.name)}-data-{doc.ref}.txt"] = body
    if len(files) == 1:
        ((name, body),) = files.items()
        media = exporters.FORMATS[formats[0]][1]
    else:
        name, body, media = f"{base}.zip", exporters.package(files, doc), "application/zip"
    return Response(body, media_type=media, headers={
        "Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    })  # fmt: skip


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
    ctx = await settings_context(request, session, case, user, "report", new_link=url)
    return render(request, "cases/deliver.html", ctx)


@router.post("/cases/{case_id}/handoff", dependencies=[Depends(verify_csrf)])
async def handoff(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    """Get the report ready to send in one step: a share link, the PDF, and a message to paste."""
    case = await get_case_for_user(session, case_id, user)
    if not _is_owner(case, user):
        return _back(case, error="not_owner")
    if not assessment_ready(case):
        return _back(case, error="assessment")
    form = await request.form()
    recipient = str(form.get("recipient") or "").strip()[:120]
    detail = "brief" if form.get("detail") == "brief" else "full"
    try:
        days = int(str(form.get("days") or 7))
    except ValueError:
        days = 7
    link, token = await create_share_link(session, case, user, days=days, label=recipient or "Hand-off")
    log_access(session, "handoff", user_id=user.id, case_id=case.id, ip=client_ip(request),
               link_id=str(link.id), expires_at=link.expires_at.isoformat(), detail=detail)  # fmt: skip
    await session.commit()
    url = str(request.base_url).rstrip("/") + f"/s/{token}"
    expires = link.expires_at.strftime("%-d %B %Y")
    greeting = f"Hi {recipient}," if recipient else "Hi,"
    message = (
        f"{greeting}\n\nHere is the {'brief' if detail == 'brief' else 'report'} for {case.name}. You can read it "
        f"online until {expires}:\n{url}\n\nThe PDF is attached. It is marked TLP:AMBER and contains personal data, "
        f"so please share it only with people who need it for this matter.\n\n{user.email}"
    )
    pdf = f"/cases/{case.id}/download?f=pdf&detail={detail}"
    ctx = await settings_context(request, session, case, user, "report",
                                 handoff={"url": url, "pdf": pdf, "message": message, "expires": expires,
                                          "recipient": recipient, "detail": detail})  # fmt: skip
    return render(request, "cases/deliver.html", ctx)


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
