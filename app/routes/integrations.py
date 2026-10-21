"""The Integrations page: enter, replace, remove and test the API keys lookup tools use."""

from __future__ import annotations

import uuid
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
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

MESSAGES = {"saved": "Saved. Tools that use it can run now.", "removed": "Removed.",
            "webhook_removed": "Webhook removed. It receives nothing from now on."}  # fmt: skip


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
    from app.models import WEBHOOK_EVENTS, Webhook

    health = {h.name: h for h in await tool_health(session)}
    hooks = (await session.scalars(select(Webhook).order_by(Webhook.created_at))).all() if user.is_admin else []
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
            "webhooks": hooks,
            "webhook_events": WEBHOOK_EVENTS,
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


# --- Webhooks -----------------------------------------------------------------------------------


@router.post("/integrations/webhooks/new", dependencies=[Depends(verify_csrf)])
async def create_webhook(
    request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    from app.services import webhooks

    _require_admin(user)
    form = await request.form()
    try:
        events = [str(e) for e in form.getlist("events")]
        hook, secret = await webhooks.create(session, url=str(form.get("url") or ""), events=events, user_id=user.id)
    except ValueError as exc:
        return await _page(request, session, user, webhook_error=str(exc))
    log_access(session, "webhook_created", user_id=user.id, ip=client_ip(request), webhook=str(hook.id),
               events=hook.events)  # fmt: skip
    await session.commit()
    # The only time the signing secret is shown.
    return await _page(request, session, user, new_secret=secret, new_hook=str(hook.id))


@router.post("/integrations/webhooks/{hook_id}/test", dependencies=[Depends(verify_csrf)])
async def test_webhook(
    request: Request, hook_id: uuid.UUID, session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):  # fmt: skip
    from datetime import UTC, datetime

    from app.models import Webhook
    from app.services import webhooks

    _require_admin(user)
    hook = await session.get(Webhook, hook_id)
    if hook is None:
        raise HTTPException(status_code=404)
    status = await webhooks.deliver(hook, "ping", {"message": "A test delivery from UNMASK."})
    hook.last_status, hook.last_delivery_at = status, datetime.now(UTC)
    log_access(session, "webhook_test", user_id=user.id, ip=client_ip(request), webhook=str(hook.id),
               status=status)  # fmt: skip
    await session.commit()
    return RedirectResponse("/integrations#webhooks", status_code=303)


@router.post("/integrations/webhooks/{hook_id}/delete", dependencies=[Depends(verify_csrf)])
async def delete_webhook(
    request: Request, hook_id: uuid.UUID, session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):  # fmt: skip
    from app.models import Webhook

    _require_admin(user)
    hook = await session.get(Webhook, hook_id)
    if hook is not None:
        await session.delete(hook)
        log_access(session, "webhook_deleted", user_id=user.id, ip=client_ip(request), webhook=str(hook_id))
        await session.commit()
    return RedirectResponse("/integrations?saved=webhook_removed#webhooks", status_code=303)


# --- Audit log export -----------------------------------------------------------------------------


@router.get("/integrations/audit.{fmt}")
async def export_audit(
    request: Request, fmt: str, days: int = 30, session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):  # fmt: skip
    """The platform's audit log for a SIEM or a records request: admins only, and the export is itself logged."""
    from fastapi.responses import Response

    from app.services.auditlog import audit_rows, to_csv, to_jsonl

    _require_admin(user)
    if fmt not in ("csv", "jsonl"):
        raise HTTPException(status_code=404)
    days = max(1, min(days, 3650))
    rows = await audit_rows(session, days=days)
    log_access(session, "audit_export", user_id=user.id, ip=client_ip(request), format=fmt, days=days, rows=len(rows))
    await session.commit()
    body = to_csv(rows) if fmt == "csv" else to_jsonl(rows)
    media = "text/csv; charset=utf-8" if fmt == "csv" else "application/x-ndjson"
    return Response(body, media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="unmask-audit-{days}d.{fmt}"'})  # fmt: skip
