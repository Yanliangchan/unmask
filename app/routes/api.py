"""Versioned public API (/api/v1) for automation: read cases and findings, start scans.

Compatibility: within v1, fields are only ever added, never renamed or removed, and an
endpoint's meaning does not change; anything breaking gets /api/v2. Every request is
authenticated with an API key (Authorization: Bearer umk_...), checked against the key's
scopes, rate-limited per key, and recorded in the audit log with the key's prefix.

The API follows the same rules as the app: a key sees exactly the cases its owner can
see; findings, the graph, paths and STIX leave the platform only for a case with a
written analyst assessment (like exports); scans count against the daily quota.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_access
from app.db import get_session
from app.models import ApiKey, Entity, Investigation, ScanRun, User
from app.security import client_ip
from app.services.apikeys import authenticate, limiter
from app.services.cases import get_case_for_user, quota_problem, visible_case_ids
from app.services.report import assessment_ready

router = APIRouter(prefix="/api/v1", tags=["v1"])
# Which findings: everything except "Not them" (visible), confirmed only, or all.
INCLUDE = Query("visible", pattern="^(visible|confirmed|all)$")
VERSION = "1.0"


class Principal:
    def __init__(self, key: ApiKey, user: User):
        self.key, self.user = key, user

    def need(self, scope: str) -> None:
        if scope not in (self.key.scopes or []):
            raise HTTPException(status_code=403, detail=f"This key does not have the {scope} permission")


async def principal(request: Request, session: AsyncSession = Depends(get_session)) -> Principal:
    from datetime import UTC

    from app.legal import needs_acceptance

    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    found = await authenticate(session, token) if token else None
    if found is None:
        raise HTTPException(status_code=401, detail="A valid API key is required (Authorization: Bearer umk_...)")
    key, user = found
    if needs_acceptance(user):
        raise HTTPException(status_code=403, detail="The key's owner must accept the current terms in the app first")
    if not limiter.allow(str(key.id)):
        raise HTTPException(status_code=429, detail="Too many requests for this key; slow down")
    key.last_used_at, key.last_used_ip = datetime.now(UTC), client_ip(request)
    return Principal(key, user)


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _run(r: ScanRun) -> dict:
    return {"number": r.run_number, "status": r.status, "triggered_by": r.triggered_by,
            "created_at": _iso(r.created_at), "started_at": _iso(r.started_at), "completed_at": _iso(r.completed_at),
            "tools": r.tools_included, "tools_failed": r.tools_failed, "jobs_total": r.jobs_total,
            "jobs_done": r.jobs_done}  # fmt: skip


async def _case(session: AsyncSession, p: Principal, case_id: uuid.UUID, *, data_out: bool = False) -> Investigation:
    case = await get_case_for_user(session, case_id, p.user)
    if data_out and not assessment_ready(case):
        raise HTTPException(status_code=409, detail="This case has no written analyst assessment yet; "
                            "findings leave the platform only with one (Case settings > Report)")  # fmt: skip
    return case


def _audit(session, request: Request, p: Principal, action: str, case_id: uuid.UUID | None = None, **detail) -> None:
    log_access(session, action, user_id=p.user.id, case_id=case_id, ip=client_ip(request), api_key=p.key.prefix,
               **detail)  # fmt: skip


@router.get("/openapi.json", include_in_schema=False)
async def openapi(request: Request):
    """The API's schema (OpenAPI 3); no key needed to read it."""
    return JSONResponse(get_openapi(title="UNMASK API", version=VERSION, routes=router.routes,
                                    description=__doc__))  # fmt: skip


@router.get("/me")
async def me(request: Request, p: Principal = Depends(principal), session: AsyncSession = Depends(get_session)):
    """Who the key acts as, and what it may do."""
    await session.commit()
    return {"user": p.user.email, "key": {"name": p.key.name, "prefix": p.key.prefix, "scopes": p.key.scopes,
                                           "expires_at": _iso(p.key.expires_at)}, "api_version": VERSION}  # fmt: skip


@router.get("/cases")
async def list_cases(request: Request, p: Principal = Depends(principal), session: AsyncSession = Depends(get_session)):
    """Every case the key's owner can see, newest first."""
    p.need("cases:read")
    ids = await visible_case_ids(session, p.user)
    cases, counts = [], {}
    if ids:
        cases = (
            await session.scalars(
                select(Investigation).where(Investigation.id.in_(ids)).order_by(Investigation.created_at.desc())
            )
        ).all()
        live = Entity.case_id.in_(ids), Entity.is_seed.is_(False), Entity.merged_into_id.is_(None)
        per_case = select(Entity.case_id, func.count(Entity.id)).where(*live).group_by(Entity.case_id)
        rows = await session.execute(per_case)
        counts = dict(rows.all())
    _audit(session, request, p, "api_list_cases", count=len(cases))
    await session.commit()
    out = [
        {"id": str(c.id), "name": c.name, "created_at": _iso(c.created_at), "sample": c.is_sample,
         "findings": counts.get(c.id, 0), "assessment_written": assessment_ready(c)}
        for c in cases
    ]  # fmt: skip
    return {"cases": out}


@router.get("/cases/{case_id}")
async def get_case(case_id: uuid.UUID, request: Request, p: Principal = Depends(principal),
                   session: AsyncSession = Depends(get_session)):  # fmt: skip
    """A case's targets and scan history (no findings: see /findings)."""
    p.need("cases:read")
    case = await _case(session, p, case_id)
    _audit(session, request, p, "api_view_case", case.id)
    await session.commit()
    return {
        "id": str(case.id), "name": case.name, "created_at": _iso(case.created_at), "sample": case.is_sample,
        "authorization_note": case.authorization_note, "assessment_written": assessment_ready(case),
        "targets": [{"type": t.type, "value": t.value, "context": t.context_tags} for t in case.targets],
        "scans": [_run(r) for r in case.scan_runs][-20:],
    }  # fmt: skip


@router.get("/cases/{case_id}/findings")
async def findings(case_id: uuid.UUID, request: Request, include: str = INCLUDE,
                   p: Principal = Depends(principal), session: AsyncSession = Depends(get_session)):  # fmt: skip
    """Findings with their scores, sources, decisions and links (the JSON export's format)."""
    from app.services.exports import export_json

    p.need("findings:read")
    case = await _case(session, p, case_id, data_out=True)
    body = await export_json(session, case, include)
    _audit(session, request, p, "api_export", case.id, format="json", scope=include)
    await session.commit()
    return body


@router.get("/cases/{case_id}/stix")
async def stix(case_id: uuid.UUID, request: Request, include: str = INCLUDE,
               p: Principal = Depends(principal), session: AsyncSession = Depends(get_session)):  # fmt: skip
    """A STIX 2.1 bundle of the case, marked TLP:AMBER."""
    from app.services.exports import export_stix

    p.need("findings:read")
    case = await _case(session, p, case_id, data_out=True)
    body = await export_stix(session, case, include)
    _audit(session, request, p, "api_export", case.id, format="stix", scope=include)
    await session.commit()
    return JSONResponse(body, media_type="application/stix+json;version=2.1")


@router.get("/cases/{case_id}/bundle")
async def bundle(case_id: uuid.UUID, request: Request, p: Principal = Depends(principal),
                 session: AsyncSession = Depends(get_session)):  # fmt: skip
    """The evidence bundle (ZIP): report, data, STIX, provenance, audit trail, snapshots, SHA-256 manifest."""
    from fastapi.responses import Response

    from app.services.bundle import build_bundle

    p.need("findings:read")
    case = await _case(session, p, case_id, data_out=True)
    _audit(session, request, p, "export_bundle", case.id)
    await session.commit()
    data, digest = await build_bundle(session, case, p.user)
    return Response(data, media_type="application/zip", headers={"X-Manifest-SHA256": digest})


@router.get("/cases/{case_id}/report")
async def report(case_id: uuid.UUID, request: Request, format: str = Query("pdf", pattern="^(pdf|docx|html|md|txt)$"),
                 detail: str = Query("full", pattern="^(full|brief)$"),
                 scope: str = Query("visible", pattern="^(visible|confirmed|all)$"),
                 p: Principal = Depends(principal), session: AsyncSession = Depends(get_session)):  # fmt: skip
    """The case report as PDF, Word, HTML, Markdown or raw text."""
    from anyio import to_thread
    from fastapi.responses import Response

    from app.services import exporters
    from app.services.document import build_document

    p.need("findings:read")
    case = await _case(session, p, case_id, data_out=True)
    _audit(session, request, p, "export_report", case.id, formats=[format], scope=scope, detail=detail)
    await session.commit()
    doc = await build_document(session, case, p.user, scope, "full" if format == "txt" else detail)
    render = {"pdf": exporters.render_pdf, "docx": exporters.render_docx, "html": exporters.render_html,
              "md": exporters.render_markdown, "txt": exporters.render_text}[format]  # fmt: skip
    body = await to_thread.run_sync(render, doc)
    return Response(body if isinstance(body, bytes) else body.encode(), media_type=exporters.FORMATS[format][1],
                    headers={"X-Report-Reference": doc.ref})  # fmt: skip


@router.get("/cases/{case_id}/graph")
async def graph(case_id: uuid.UUID, request: Request, p: Principal = Depends(principal),
                session: AsyncSession = Depends(get_session)):  # fmt: skip
    """Findings and links, each link with the evidence behind it (the graph workspace's data)."""
    from app.services.graph import case_graph

    p.need("findings:read")
    case = await _case(session, p, case_id, data_out=True)
    body = await case_graph(session, case.id, include_all=True)
    _audit(session, request, p, "api_export", case.id, format="graph")
    await session.commit()
    return body


@router.get("/cases/{case_id}/paths")
async def paths(case_id: uuid.UUID, a: uuid.UUID, b: uuid.UUID, request: Request,
                p: Principal = Depends(principal), session: AsyncSession = Depends(get_session)):  # fmt: skip
    """The strongest evidence paths between two findings. Association through evidence, not identity."""
    from app.services.graph import case_graph
    from app.services.paths import find_paths

    p.need("findings:read")
    case = await _case(session, p, case_id, data_out=True)
    body = find_paths(await case_graph(session, case.id, include_all=True), str(a), str(b))
    _audit(session, request, p, "api_paths", case.id)
    await session.commit()
    return body


@router.post("/cases/{case_id}/scans", status_code=202)
async def start_scan(case_id: uuid.UUID, request: Request, p: Principal = Depends(principal),
                     session: AsyncSession = Depends(get_session)):  # fmt: skip
    """Start a scan with the case's tools, or return the one already running."""
    from app.services.scans import active_run, create_scan_run, dispatch

    p.need("scans:write")
    case = await _case(session, p, case_id)
    if case.is_sample:
        raise HTTPException(status_code=400, detail="Sample cases use made-up data and can't be scanned")
    if (problem := await quota_problem(session, p.user, new_scans=1)) is not None:
        raise HTTPException(status_code=429, detail=problem)
    run = await active_run(session, case.id)
    if run is None:
        run = await create_scan_run(session, case, triggered_by="manual")
        _audit(session, request, p, "run_scan", case.id, run_number=run.run_number)
        await session.commit()
        await dispatch(run.id, run.triggered_by)
        await session.refresh(run)
    else:
        await session.commit()
    return _run(run)


@router.get("/cases/{case_id}/scans/{number}")
async def scan_status(case_id: uuid.UUID, number: int, request: Request, p: Principal = Depends(principal),
                      session: AsyncSession = Depends(get_session)):  # fmt: skip
    """One scan's progress: poll this after starting one."""
    p.need("cases:read")
    case = await _case(session, p, case_id)
    run = await session.scalar(select(ScanRun).where(ScanRun.case_id == case.id, ScanRun.run_number == number))
    if run is None:
        raise HTTPException(status_code=404, detail="No such scan")
    await session.commit()
    return _run(run)


@router.get("/audit")
async def audit(request: Request, since: datetime | None = None, limit: int = Query(1000, ge=1, le=10_000),
                p: Principal = Depends(principal), session: AsyncSession = Depends(get_session)):  # fmt: skip
    """Audit log entries from `since` (ISO time; default the last 24 hours), oldest first. Page with the last
    entry's timestamp. Administrators only, with the audit:read permission."""
    from datetime import UTC, timedelta

    from app.services.auditlog import audit_rows

    p.need("audit:read")
    if not p.user.is_admin:
        raise HTTPException(status_code=403, detail="Only administrators can read the audit log")
    start = since or datetime.now(UTC) - timedelta(days=1)
    rows = await audit_rows(session, since=start, limit=limit)
    _audit(session, request, p, "audit_export", format="api", rows=len(rows))
    await session.commit()
    return {"entries": rows, "next_since": rows[-1]["timestamp"] if len(rows) == limit else None}
