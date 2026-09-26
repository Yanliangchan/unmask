from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_access
from app.db import get_session
from app.models import User
from app.security import client_ip, current_user_optional, login_limiter, verify_csrf, verify_password
from app.web import Seo, render

router = APIRouter()


def _safe_next(target: str | None) -> str:
    # Only allow local redirects to prevent open-redirects after login.
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return "/"


@router.get("/login")
async def login_form(request: Request, next: str | None = None, user: User | None = Depends(current_user_optional)):
    if user is not None:
        return RedirectResponse(_safe_next(next), status_code=303)
    return render(request, "auth/login.html", {"seo": Seo(title="Sign in", path="/login"), "next": _safe_next(next)})


@router.post("/login", dependencies=[Depends(verify_csrf)])
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form("/"),
    session: AsyncSession = Depends(get_session),
):
    ip = client_ip(request)
    email_norm = email.strip().lower()
    ctx = {"seo": Seo(title="Sign in", path="/login"), "next": _safe_next(next), "email": email_norm}
    if login_limiter.is_blocked(ip, email_norm):
        log_access(session, "login_blocked", user_id=None, ip=ip, email=email_norm)
        await session.commit()
        return render(
            request,
            "auth/login.html",
            {**ctx, "error": "Too many failed attempts. Try again in 15 minutes."},
            status_code=429,
        )
    user = await session.scalar(select(User).where(User.email == email_norm))
    ok = verify_password(user.password_hash if user else None, password)
    if not ok or user is None or not user.is_active:
        login_limiter.record_failure(ip, email_norm)
        log_access(session, "login_failed", user_id=user.id if user else None, ip=ip)
        await session.commit()
        return render(request, "auth/login.html", {**ctx, "error": "Invalid email or password."}, status_code=401)

    login_limiter.reset(ip, email_norm)
    request.session.clear()  # new session on privilege change
    request.session["user_id"] = str(user.id)
    user.last_login_at = datetime.now(UTC)
    log_access(session, "login", user_id=user.id, ip=ip)
    await session.commit()
    return RedirectResponse(_safe_next(next), status_code=303)


@router.post("/logout", dependencies=[Depends(verify_csrf)])
async def logout(
    request: Request,
    session: AsyncSession = Depends(get_session),
    user: User | None = Depends(current_user_optional),
):
    if user is not None:
        log_access(session, "logout", user_id=user.id, ip=client_ip(request))
        await session.commit()
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
