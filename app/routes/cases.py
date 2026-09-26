from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.registry import all_adapters, get_adapter
from app.audit import log_access
from app.correlation.engine import lock_case, rescore_case
from app.db import get_session
from app.jobs import enqueue_health_check, enqueue_scan, uses_rq, worker_count
from app.models import TARGET_TYPES, Entity, PivotLog, ScanRun, User
from app.pivots.engine import auto_pivot_enabled
from app.routes.public import render_landing
from app.scheduler import watch_state
from app.security import client_ip, current_user, current_user_optional, verify_csrf
from app.services.cases import (
    CaseValidationError,
    TargetInput,
    create_case,
    get_case_for_user,
    list_cases_for_user,
    mark_reviewed,
    parse_tags,
)
from app.services.entities import EntityFilters, entity_detail, list_entities
from app.services.graph import case_graph
from app.services.scans import create_scan_run
from app.services.tools import run_health_check, tool_configs, tool_health
from app.web import Seo, render

router = APIRouter()

TARGET_TYPE_LABELS = {
    "username": "Username",
    "email": "Email",
    "domain": "Domain",
    "phone": "Phone",
    "ip": "IP address",
    "name": "Full name",
    "image": "Image (URL)",
}


def _is_htmx(request: Request) -> bool:
    return request.headers.get("hx-request") == "true"


# --- Dashboard ----------------------------------------------------------------


@router.api_route("/", methods=["GET", "HEAD"])
async def dashboard(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_user_optional),
):
    if user is None:
        return render_landing(request)
    cards = await list_cases_for_user(session, user)
    health = await tool_health(session)
    return render(
        request,
        "dashboard.html",
        {
            "seo": Seo(title="Investigations", path="/"),
            "user": user,
            "cards": cards,
            "health": health,
            "workers": worker_count(),
        },
    )


@router.get("/partials/tool-health")
async def tool_health_partial(
    request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    return render(
        request,
        "partials/tool_health.html",
        {"health": await tool_health(session), "user": user, "workers": worker_count()},
    )


@router.post("/tools/{tool_name}/health-check", dependencies=[Depends(verify_csrf)])
async def tool_health_check(
    request: Request,
    tool_name: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    if get_adapter(tool_name) is None:
        raise HTTPException(status_code=404, detail="Unknown tool")
    notice = None
    if uses_rq():
        # Health checks can take minutes; run them on a worker, not in the request.
        enqueue_health_check(tool_name)
        notice = f"Health check for {tool_name} queued — the panel refreshes when it finishes."
    else:
        await run_health_check(session, tool_name)
    log_access(session, "tool_health_check", user_id=user.id, ip=client_ip(request), tool=tool_name)
    await session.commit()
    return render(
        request,
        "partials/tool_health.html",
        {"health": await tool_health(session), "user": user, "notice": notice, "workers": worker_count()},
    )


# --- Case creation ------------------------------------------------------------


async def _tool_choices(session: AsyncSession) -> list[dict]:
    cfgs = await tool_configs(session)
    return [
        {
            "name": a.name,
            "label": a.label,
            "description": a.description,
            "input_types": a.input_types,
            "enabled": bool(cfgs.get(a.name) and cfgs[a.name].enabled) and a.configured() is None,
            "unavailable_reason": a.configured()
            or (None if cfgs.get(a.name) and cfgs[a.name].enabled else "currently disabled"),
        }
        for a in all_adapters()
    ]


def _new_case_context(user: User, tools: list[dict], **extra) -> dict:
    return {
        "seo": Seo(title="New case", path="/cases/new"),
        "user": user,
        "target_types": [(t, TARGET_TYPE_LABELS[t]) for t in TARGET_TYPES],
        "tools": tools,
        **extra,
    }


@router.get("/cases/new")
async def new_case_form(
    request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    tools = await _tool_choices(session)
    return render(
        request,
        "cases/new.html",
        _new_case_context(user, tools, form={"targets": [{"value": "", "type": "username", "tags": ""}]}),
    )


@router.post("/cases", dependencies=[Depends(verify_csrf)])
async def create_case_submit(
    request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    form = await request.form()
    values = form.getlist("target_value")
    types = form.getlist("target_type")
    tags = form.getlist("target_tags")
    targets = [
        TargetInput(value=str(v), type=str(t), context_tags=parse_tags(str(g)))
        for v, t, g in zip(values, types, tags + [""] * (len(values) - len(tags)), strict=False)
    ]
    tools = await _tool_choices(session)
    selected = set(map(str, form.getlist("tools")))
    disabled = [t["name"] for t in tools if t["enabled"] and t["name"] not in selected]
    try:
        case = await create_case(
            session,
            owner=user,
            name=str(form.get("name", "")),
            authorization_note=str(form.get("authorization_note", "")),
            lawful_basis_confirmed=form.get("lawful_basis_confirmed") == "on",
            targets=targets,
            disabled_tools=disabled,
            notes=str(form.get("notes", "")),
        )
    except CaseValidationError as exc:
        # Validation runs before anything is added to the session, so there is
        # nothing to roll back (and rolling back would expire `user`).
        echo = {
            "name": form.get("name", ""),
            "authorization_note": form.get("authorization_note", ""),
            "notes": form.get("notes", ""),
            "targets": [{"value": t.value, "type": t.type, "tags": ", ".join(t.context_tags)} for t in targets]
            or [{"value": "", "type": "username", "tags": ""}],
        }
        for t in tools:
            t["checked"] = t["name"] in selected
        return render(
            request,
            "cases/new.html",
            _new_case_context(user, tools, form=echo, errors=exc.errors),
            status_code=422,
        )
    run = await create_scan_run(session, case, triggered_by="manual")
    ip = client_ip(request)
    log_access(session, "create_case", user_id=user.id, case_id=case.id, ip=ip, targets=len(targets))
    log_access(session, "run_scan", user_id=user.id, case_id=case.id, ip=ip, run_number=run.run_number)
    await session.commit()
    enqueue_scan(run.id, run.triggered_by)
    return RedirectResponse(f"/cases/{case.id}", status_code=303)


# --- Case workspace -----------------------------------------------------------


@router.get("/cases/{case_id}")
async def workspace(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    latest = case.scan_runs[-1] if case.scan_runs else None
    log_access(session, "view_case", user_id=user.id, case_id=case.id, ip=client_ip(request))
    await session.commit()
    return render(
        request,
        "cases/workspace.html",
        {
            "seo": Seo(title=case.name, path=f"/cases/{case.id}"),
            "user": user,
            "case": case,
            "latest_run": latest,
            "workers": worker_count(),
            "auto_pivot": auto_pivot_enabled(case),
            "watch": watch_state(case),
            "pivot_count": await session.scalar(
                select(func.count()).select_from(PivotLog).where(PivotLog.case_id == case.id)
            ),
            **await _entity_filter_options(session, case),
        },
    )


async def _entity_filter_options(session: AsyncSession, case) -> dict:
    types = (await session.scalars(select(Entity.type).where(Entity.case_id == case.id).distinct())).all()
    return {"entity_types": sorted(types), "tool_names": [a.name for a in all_adapters()] + ["analyst"]}


def _filters_from_query(request: Request) -> EntityFilters:
    q = request.query_params
    try:
        min_conf = float(q.get("min_confidence") or 0)
    except ValueError:
        min_conf = 0.0
    return EntityFilters(
        type=q.get("type") or None,
        min_confidence=max(0.0, min(1.0, min_conf)),
        tools=[t for t in q.getlist("tool") if t],
        confirmed_only=q.get("confirmed_only") in ("on", "true", "1"),
    )


@router.get("/cases/{case_id}/entities")
async def entities_partial(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    rows = await list_entities(session, case.id, _filters_from_query(request))
    await mark_reviewed(session, case)
    await session.commit()
    return render(request, "cases/_entities_table.html", {"case": case, "rows": rows})


@router.get("/cases/{case_id}/entities/{entity_id}")
async def entity_detail_partial(
    request: Request,
    case_id: uuid.UUID,
    entity_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    detail = await entity_detail(session, case.id, entity_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    return render(request, "cases/_entity_detail.html", {"case": case, "d": detail, "entity": detail.entity})


@router.post("/cases/{case_id}/entities/{entity_id}/confirm", dependencies=[Depends(verify_csrf)])
async def toggle_confirm(
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
    entity.confirmed_flag = not entity.confirmed_flag
    log_access(
        session,
        "confirm_entity" if entity.confirmed_flag else "unconfirm_entity",
        user_id=user.id,
        case_id=case.id,
        ip=client_ip(request),
        entity_id=str(entity.id),
    )
    # Confirmation is a human override: rescore so it takes effect at once.
    await lock_case(session, case.id)
    await rescore_case(session, case.id)
    await session.commit()
    rows = await list_entities(session, case.id, EntityFilters())
    row = next((r for r in rows if r.entity.id == entity.id), None)
    return render(request, "cases/_entity_row.html", {"case": case, "row": row})


# --- Scans --------------------------------------------------------------------


@router.post("/cases/{case_id}/scans", dependencies=[Depends(verify_csrf)])
async def run_scan(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    active = [r for r in case.scan_runs if r.status in ("queued", "running")]
    if active:
        run = active[-1]
    else:
        run = await create_scan_run(session, case, triggered_by="manual")
        log_access(
            session, "run_scan", user_id=user.id, case_id=case.id, ip=client_ip(request), run_number=run.run_number
        )
        await session.commit()
        enqueue_scan(run.id, run.triggered_by)
    if _is_htmx(request):
        return render(request, "partials/scan_status.html", {"case": case, "run": run, "workers": worker_count()})
    return RedirectResponse(f"/cases/{case.id}", status_code=303)


@router.get("/cases/{case_id}/scan-status")
async def scan_status(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    run = await session.scalar(
        select(ScanRun).where(ScanRun.case_id == case.id).order_by(ScanRun.run_number.desc()).limit(1)
    )
    response = render(request, "partials/scan_status.html", {"case": case, "run": run, "workers": worker_count()})
    if run is not None and run.status not in ("queued", "running") and request.query_params.get("was_running"):
        # Tell the page to refresh the entity table now that results are in.
        response.headers["HX-Trigger"] = "scan-finished"
    return response


@router.get("/cases/{case_id}/tab/{tab}", response_class=HTMLResponse)
async def case_tab(
    request: Request,
    case_id: uuid.UUID,
    tab: str,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    if tab == "entities":
        return render(
            request, "cases/_entities_tab.html", {"case": case, **await _entity_filter_options(session, case)}
        )
    if tab != "graph":
        raise HTTPException(status_code=404)
    return render(request, "cases/_graph_tab.html", {"case": case})


@router.get("/cases/{case_id}/graph.json")
async def graph_json(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    return JSONResponse(await case_graph(session, case.id))
