"""Importing findings into a case: check a file first, then commit exactly what was checked."""

from __future__ import annotations

import uuid

from cryptography.fernet import InvalidToken
from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import log_access
from app.correlation.engine import correlate_and_commit, lock_case
from app.db import get_session
from app.models import User
from app.routes.settings import settings_context
from app.security import client_ip, current_user, verify_csrf
from app.services import importer
from app.services.cases import get_case_for_user
from app.web import render

router = APIRouter()


async def _case(session: AsyncSession, case_id: uuid.UUID, user: User):
    case = await get_case_for_user(session, case_id, user)
    if case.is_sample:
        raise HTTPException(status_code=400, detail="Sample cases use made-up data; nothing can be imported")
    return case


@router.post("/cases/{case_id}/import/check", dependencies=[Depends(verify_csrf)])
async def check_import(
    request: Request,
    case_id: uuid.UUID,
    file: UploadFile,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await _case(session, case_id, user)
    raw = await file.read(importer.MAX_BYTES + 1)
    extra: dict = {}
    try:
        plan = importer.check(raw, file.filename or "upload.json")
        extra = {"import_plan": plan, "import_token": plan.seal()}
    except importer.ImportError_ as exc:
        extra = {"import_error": str(exc)}
    ctx = await settings_context(request, session, case, user, **extra)
    return render(request, "cases/settings.html", ctx, status_code=200 if "import_plan" in extra else 422)


@router.post("/cases/{case_id}/import/commit", dependencies=[Depends(verify_csrf)])
async def commit_import(
    request: Request,
    case_id: uuid.UUID,
    token: str = Form(...),
    session: AsyncSession = Depends(get_session),
    user: User = Depends(current_user),
):
    case = await _case(session, case_id, user)
    try:
        plan = importer.Plan.unseal(token)
    except (InvalidToken, ValueError, KeyError, TypeError):
        raise HTTPException(
            status_code=400, detail="That import has expired or was changed; check the file again"
        ) from None
    if not plan.items:
        return RedirectResponse(f"/cases/{case.id}/settings#import", status_code=303)
    await lock_case(session, case.id)
    run = await importer.commit(session, case, user, plan)
    log_access(session, "import_findings", user_id=user.id, case_id=case.id, ip=client_ip(request),
               format=plan.format, findings=len(plan.items), links=len(plan.links), invalid=len(plan.invalid),
               run_number=run.run_number)  # fmt: skip
    await session.commit()
    await correlate_and_commit(session, case.id, semantic=False)
    return RedirectResponse(f"/cases/{case.id}?show=all&tool=import", status_code=303)
