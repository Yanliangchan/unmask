"""The Integrations page: enter, replace, remove and test the API keys lookup tools use."""

from __future__ import annotations

from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app import integrations as integ
from app.adapters.registry import get_adapter
from app.audit import log_access
from app.db import get_session
from app.models import AppSecret, User
from app.security import client_ip, current_user, verify_csrf
from app.services.tools import run_health_check, tool_health
from app.web import Seo, render

router = APIRouter()

MESSAGES = {"saved": "Saved. Tools that use it can run now.", "removed": "Removed."}


def _require_admin(user: User) -> None:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Only administrators can change integrations")


def _validate(field: integ.KeyField, value: str) -> str | None:
    if len(value) > field.max_length:
        return f"{field.label} is too long"
    if field.setting == "proxy_url":
        parts = urlsplit(value)
        if parts.scheme not in ("http", "https", "socks5", "socks5h") or not parts.hostname:
            return "The proxy URL must look like http://user:password@host:port or socks5://host:port"
    elif field.setting != "h8mail_keys" and any(ch.isspace() for ch in value):
        return f"{field.label} shouldn't contain spaces; check it was copied whole"
    return None


async def _page(request: Request, session: AsyncSession, user: User, **extra):
    health = {h.name: h for h in await tool_health(session)}
    return render(
        request,
        "integrations.html",
        {
            "seo": Seo(title="Integrations", path="/integrations"),
            "user": user,
            "catalog": integ.CATALOG,
            "categories": integ.CATEGORIES,
            "integ": integ,
            "health": health,
            "connected": sum(1 for i in integ.CATALOG if integ.is_set(i)),
            "message": MESSAGES.get(request.query_params.get("saved", "")),
            **extra,
        },
        status_code=422 if extra.get("error") else 200,
    )


@router.get("/integrations")
async def integrations_page(
    request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    await integ.refresh(session, force=True)
    return await _page(request, session, user)


@router.post("/integrations/{key}", dependencies=[Depends(verify_csrf)])
async def save_integration(
    request: Request, key: str, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    _require_admin(user)
    item = integ.BY_KEY.get(key)
    if item is None:
        raise HTTPException(status_code=404)
    form = await request.form()
    remove = form.get("remove") == "1"
    changed = []
    for field in item.fields:
        row = await session.get(AppSecret, field.setting)
        if remove:
            if row is not None:
                await session.delete(row)
                changed.append(field.setting)
            continue
        value = str(form.get(field.setting) or "").strip()
        if not value:
            continue  # blank keeps what's saved: saved keys are never sent back to the browser
        if problem := _validate(field, value):
            return await _page(request, session, user, error=problem, error_key=key)
        if row is None:
            session.add(AppSecret(name=field.setting, value=value, updated_by=user.id))
        else:
            row.value, row.updated_by = value, user.id
        changed.append(field.setting)
    if changed:
        # Which settings changed, never their values.
        log_access(session, "integration_remove" if remove else "integration_update", user_id=user.id,
                   ip=client_ip(request), integration=key, settings=changed)  # fmt: skip
        await session.commit()
        await integ.refresh(session, force=True)
    return RedirectResponse(f"/integrations?saved={'removed' if remove else 'saved'}#{key}", status_code=303)


@router.post("/integrations/{key}/test", dependencies=[Depends(verify_csrf)])
async def test_integration(
    request: Request, key: str, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    _require_admin(user)
    item = integ.BY_KEY.get(key)
    if item is None:
        raise HTTPException(status_code=404)
    await integ.refresh(session, force=True)
    results = []
    for name in item.tools:
        adapter = get_adapter(name)
        if adapter is None:
            continue
        if missing := adapter.configured():
            results.append((adapter.label, False, missing))
            continue
        h = await run_health_check(session, name)
        results.append((adapter.label, h.status == "ok", h.detail))
    log_access(session, "integration_test", user_id=user.id, ip=client_ip(request), integration=key,
               ok=all(ok for _, ok, _ in results))  # fmt: skip
    await session.commit()
    return await _page(request, session, user, tested=key, test_results=results)
