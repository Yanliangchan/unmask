"""Global search: the search page and the command palette's results."""

from __future__ import annotations

from dataclasses import asdict

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.models import User
from app.security import current_user
from app.services.search import MIN_QUERY, global_search
from app.web import Seo, render

router = APIRouter()


@router.get("/search")
async def search_page(
    request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)
):
    q = (request.query_params.get("q") or "").strip()[:200]
    hits = await global_search(session, user, q, limit=200) if q else []
    groups: dict[str, list] = {}
    for h in hits:
        groups.setdefault(h.group, []).append(h)
    return render(
        request,
        "search.html",
        {
            "seo": Seo(title="Search", path="/search"),
            "user": user,
            "q": q,
            "groups": groups,
            "too_short": bool(q) and len(q) < MIN_QUERY,
        },  # fmt: skip
    )


@router.get("/palette.json")
async def palette(request: Request, session: AsyncSession = Depends(get_session), user: User = Depends(current_user)):
    q = (request.query_params.get("q") or "").strip()[:200]
    hits = await global_search(session, user, q, limit=12)
    return JSONResponse({"results": [asdict(h) for h in hits]})
