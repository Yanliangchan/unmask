"""Home actions, notifications, account settings and each case's activity feed."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_access
from app.db import get_session
from app.legal import needs_acceptance
from app.models import User
from app.routes.shell import case_shell
from app.security import client_ip, current_user, current_user_optional, verify_csrf
from app.services.activity import case_activity
from app.services.cases import get_case_for_user
from app.services.home import create_sample_case, sample_case_id
from app.services.notifications import (
    KINDS,
    email_configured,
    mark_all_read,
    prefs_for,
    recent,
    unread_count,
    valid_webhook,
)
from app.web import Seo, render

router = APIRouter()


# --- Getting started ------------------------------------------------------------------------------


def _set_pref(user: User, key: str, value) -> None:
    # Reassign so SQLAlchemy sees the JSONB change.
    user.preferences = {**(user.preferences or {}), key: value}


@router.post("/onboarding/dismiss", dependencies=[Depends(verify_csrf)])
async def dismiss_onboarding(session: AsyncSession = Depends(get_session), user: User = Depends(current_user)):
    _set_pref(user, "onboarding_dismissed", True)
    await session.commit()
    return RedirectResponse("/", status_code=303)


@router.post("/onboarding/sample", dependencies=[Depends(verify_csrf)])
async def open_sample_case(
    request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    existing = await sample_case_id(session, user)
    if existing:
        return RedirectResponse(f"/cases/{existing}", status_code=303)
    from app.services.home import has_real_case

    if await has_real_case(session, user):
        # The sample is for getting started; once there's real work it isn't offered again.
        return RedirectResponse("/", status_code=303)
    case = await create_sample_case(session, user)
    log_access(session, "create_case", user_id=user.id, case_id=case.id, ip=client_ip(request), sample=True)
    await session.commit()
    return RedirectResponse(f"/cases/{case.id}", status_code=303)


@router.post("/onboarding/sample/remove", dependencies=[Depends(verify_csrf)])
async def remove_sample_case(session: AsyncSession = Depends(get_session), user: User = Depends(current_user)):
    from app.services.home import retire_sample

    await retire_sample(session, user.id, reason="sample_removed")
    await session.commit()
    return RedirectResponse("/", status_code=303)


# --- Notifications ------------------------------------------------------------------------------


@router.get("/notifications")
async def notifications_page(
    request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    items = await recent(session, user.id, limit=100)
    unread = {n.id for n in items if n.read_at is None}
    # Opening the list reads them; the ones that were new stay highlighted for this view.
    await mark_all_read(session, user.id)
    await session.commit()
    return render(
        request,
        "notifications.html",
        {"seo": Seo(title="Notifications", path="/notifications"), "user": user, "items": items, "unread": unread},
    )


@router.get("/notifications/badge")
async def notifications_badge(
    session: AsyncSession = Depends(get_session), user: User | None = Depends(current_user_optional)
):
    # Polled from every page, including the terms page: never redirect from here.
    if user is None or needs_acceptance(user):
        return HTMLResponse("")
    n = await unread_count(session, user.id)
    label = f"{n} unread notification{'s' if n != 1 else ''}"
    body = f'<span class="nav-badge" aria-label="{label}">{n if n < 100 else "99+"}</span>' if n else ""
    return HTMLResponse(body)


@router.post("/notifications/read", dependencies=[Depends(verify_csrf)])
async def notifications_read(session: AsyncSession = Depends(get_session), user: User = Depends(current_user)):
    await mark_all_read(session, user.id)
    await session.commit()
    return RedirectResponse("/notifications", status_code=303)


# --- Account ------------------------------------------------------------------------------------

ACCOUNT_MESSAGES = {
    "saved": "Notification settings saved.",
    "checklist": "The getting-started checklist is back on Home.",
}


def _account(request: Request, user: User, *, error: str | None = None, status_code: int = 200):
    return render(
        request,
        "account.html",
        {
            "seo": Seo(title="Account", path="/account"),
            "user": user,
            "prefs": prefs_for(user),
            "kinds": KINDS,
            "email_ready": email_configured(),
            "webhook_set": bool(user.slack_webhook),
            "saved": ACCOUNT_MESSAGES.get(request.query_params.get("saved", "")),
            "error": error,
        },
        status_code=status_code,
    )


@router.get("/account")
async def account_page(request: Request, user: User = Depends(current_user)):
    return _account(request, user)


@router.post("/account/notifications", dependencies=[Depends(verify_csrf)])
async def save_notifications(
    request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    form = await request.form()
    webhook = str(form.get("slack_webhook") or "").strip()
    if form.get("remove_webhook"):
        user.slack_webhook = None
    elif webhook:
        problem = valid_webhook(webhook)
        if problem:
            return _account(request, user, error=problem, status_code=422)
        user.slack_webhook = webhook
    kinds = [k for k in form.getlist("kinds") if k in KINDS]
    _set_pref(user, "notify", {
        "email": form.get("email") == "on",
        "slack": form.get("slack") == "on" and bool(user.slack_webhook),
        "kinds": kinds,
    })  # fmt: skip
    log_access(session, "notification_settings", user_id=user.id, ip=client_ip(request),
               email=form.get("email") == "on", slack=bool(user.slack_webhook))  # fmt: skip
    await session.commit()
    return RedirectResponse("/account?saved=saved", status_code=303)


@router.post("/account/checklist", dependencies=[Depends(verify_csrf)])
async def restore_checklist(session: AsyncSession = Depends(get_session), user: User = Depends(current_user)):
    _set_pref(user, "onboarding_dismissed", False)
    await session.commit()
    return RedirectResponse("/account?saved=checklist", status_code=303)


# --- Case activity ------------------------------------------------------------------------------


@router.get("/cases/{case_id}/activity")
async def activity_page(
    request: Request,
    case_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await get_case_for_user(session, case_id, user)
    ctx = await case_shell(session, case, user, "activity")
    days: list[tuple[str, list]] = []
    for event in await case_activity(session, case.id):
        label = event.at.strftime("%A %-d %B %Y")
        if not days or days[-1][0] != label:
            days.append((label, []))
        days[-1][1].append(event)
    return render(request, "cases/activity.html", {**ctx, "days": days})
