"""Case Settings screen and report export."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_access
from app.db import get_session
from app.models import Investigation, User
from app.routes.shell import case_shell
from app.scheduler import FREQUENCY_DAYS, purge_date, set_watch, watch_state
from app.security import client_ip, current_user, verify_csrf
from app.services.cases import delete_case, get_case_for_user
from app.services.report import MIN_ASSESSMENT_CHARS, AssessmentRequired, build_report, render_markdown
from app.web import Seo, render

router = APIRouter()

MESSAGES = {
    "watch": "Watch mode saved.",
    "retention": "Retention saved.",
    "assessment": "Analyst assessment saved.",
    "shared": "Case shared.",
    "unshared": "Access removed.",
    "pivot": "Auto-pivot setting saved.",
}


def _is_owner(case: Investigation, user: User) -> bool:
    return case.owner_id == user.id or user.is_admin


def _back(case: Investigation, saved: str | None = None, error: str | None = None) -> RedirectResponse:
    q = f"?saved={saved}" if saved else f"?error={error}" if error else ""
    return RedirectResponse(f"/cases/{case.id}/settings{q}", status_code=303)


@router.get("/cases/{case_id}/settings")
async def settings_page(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    shared = (
        (await session.scalars(select(User).where(User.id.in_(case.shared_with or [])))).all()
        if case.shared_with
        else []
    )
    owner = await session.get(User, case.owner_id) if case.owner_id else None
    error = request.query_params.get("error")
    ctx = await case_shell(session, case, user, "settings")
    return render(
        request,
        "cases/settings.html",
        {
            **ctx,
            "owner": owner,
            "is_owner": _is_owner(case, user),
            "frequencies": list(FREQUENCY_DAYS),
            "purge_at": await purge_date(session, case),
            "shared": shared,
            "min_assessment": MIN_ASSESSMENT_CHARS,
            "message": MESSAGES.get(request.query_params.get("saved", "")),
            "error": error if error in ERRORS else None,
            "errors": ERRORS,
        },
    )


ERRORS = {
    "no_user": "No user with that email address.",
    "not_owner": "Only the case owner can do that.",
    "confirm": "Type the case name exactly to confirm deletion.",
    "assessment": f"Write an analyst assessment of at least {MIN_ASSESSMENT_CHARS} characters before exporting.",
}


@router.post("/cases/{case_id}/settings/watch", dependencies=[Depends(verify_csrf)])
async def save_watch(
    request: Request,
    case_id: uuid.UUID,
    enabled: str | None = Form(None),
    frequency: str = Form("weekly"),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    set_watch(case, enabled=enabled == "on", frequency=frequency)
    log_access(
        session, "watch_settings", user_id=user.id, case_id=case.id, ip=client_ip(request),
        enabled=enabled == "on", frequency=watch_state(case)["frequency"],
    )  # fmt: skip
    await session.commit()
    return _back(case, "watch")


@router.post("/cases/{case_id}/settings/retention", dependencies=[Depends(verify_csrf)])
async def save_retention(
    request: Request,
    case_id: uuid.UUID,
    retention_days: int = Form(...),
    permanently_active: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    case.retention_days = max(1, min(3650, retention_days))
    case.permanently_active = permanently_active == "on"
    log_access(
        session, "retention_settings", user_id=user.id, case_id=case.id, ip=client_ip(request),
        retention_days=case.retention_days, permanently_active=case.permanently_active,
    )  # fmt: skip
    await session.commit()
    return _back(case, "retention")


@router.post("/cases/{case_id}/settings/pivot", dependencies=[Depends(verify_csrf)])
async def save_pivot(
    request: Request,
    case_id: uuid.UUID,
    auto_pivot: str | None = Form(None),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    enabled = auto_pivot == "on"
    case.watch_config = {**(case.watch_config or {}), "auto_pivot": enabled}
    log_access(
        session, "auto_pivot_on" if enabled else "auto_pivot_off", user_id=user.id, case_id=case.id,
        ip=client_ip(request),
    )  # fmt: skip
    await session.commit()
    return _back(case, "pivot")


@router.post("/cases/{case_id}/settings/assessment", dependencies=[Depends(verify_csrf)])
async def save_assessment(
    request: Request,
    case_id: uuid.UUID,
    analyst_assessment: str = Form(""),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    case.analyst_assessment = analyst_assessment.strip()[:20000] or None
    case.analyst_assessment_updated_at = datetime.now(UTC)
    log_access(
        session, "analyst_assessment", user_id=user.id, case_id=case.id, ip=client_ip(request),
        length=len(case.analyst_assessment or ""),
    )  # fmt: skip
    await session.commit()
    return _back(case, "assessment")


@router.post("/cases/{case_id}/settings/share", dependencies=[Depends(verify_csrf)])
async def share(
    request: Request,
    case_id: uuid.UUID,
    email: str = Form(...),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    if not _is_owner(case, user):
        return _back(case, error="not_owner")
    other = await session.scalar(select(User).where(User.email == email.strip().lower(), User.is_active.is_(True)))
    if other is None:
        return _back(case, error="no_user")
    if other.id != case.owner_id and other.id not in (case.shared_with or []):
        case.shared_with = [*(case.shared_with or []), other.id]
        from app.services.notifications import notify

        await notify(session, other.id, kind="shared", case_id=case.id, url=f"/cases/{case.id}",
                     text=f"{user.email} shared the case {case.name} with you")  # fmt: skip
    log_access(session, "share_case", user_id=user.id, case_id=case.id, ip=client_ip(request), with_user=str(other.id))
    await session.commit()
    return _back(case, "shared")


@router.post("/cases/{case_id}/settings/unshare", dependencies=[Depends(verify_csrf)])
async def unshare(
    request: Request,
    case_id: uuid.UUID,
    user_id: uuid.UUID = Form(...),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    if not _is_owner(case, user):
        return _back(case, error="not_owner")
    case.shared_with = [u for u in (case.shared_with or []) if u != user_id]
    log_access(session, "unshare_case", user_id=user.id, case_id=case.id, ip=client_ip(request), with_user=str(user_id))
    await session.commit()
    return _back(case, "unshared")


@router.post("/cases/{case_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete(
    request: Request,
    case_id: uuid.UUID,
    confirm_name: str = Form(""),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    if not _is_owner(case, user):
        return _back(case, error="not_owner")
    if confirm_name.strip() != case.name:
        return _back(case, error="confirm")
    await delete_case(session, case.id, user_id=user.id, action="delete_case", ip=client_ip(request))
    await session.commit()
    return RedirectResponse("/", status_code=303)


# --- Report -------------------------------------------------------------------------------


async def _report(request: Request, session: AsyncSession, case_id: uuid.UUID, user: User, fmt: str):
    case = await get_case_for_user(session, case_id, user)
    try:
        report = await build_report(session, case, user)
    except AssessmentRequired:
        return case, None
    log_access(session, "export_report", user_id=user.id, case_id=case.id, ip=client_ip(request), format=fmt)
    await session.commit()
    return case, report


@router.get("/cases/{case_id}/report")
async def report_html(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case, report = await _report(request, session, case_id, user, "html")
    if report is None:
        return _back(case, error="assessment")
    return render(
        request,
        "cases/report.html",
        {"seo": Seo(title=f"Report · {case.name}", path=f"/cases/{case.id}/report"), "user": user, "r": report},
    )


@router.get("/cases/{case_id}/report.md")
async def report_markdown(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case, report = await _report(request, session, case_id, user, "markdown")
    if report is None:
        return _back(case, error="assessment")
    stamp = report.generated_at.strftime("%Y%m%d-%H%M")
    return PlainTextResponse(
        render_markdown(report),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="unmask-case-{case.id}-{stamp}.md"'},
    )
