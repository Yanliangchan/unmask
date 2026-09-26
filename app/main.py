from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.crypto import cipher
from app.db import dispose_engine, sessionmaker
from app.routes import auth, cases, correlation, pivots, public, watch
from app.routes import settings as settings_routes
from app.security import LoginRequired, ensure_admin_user
from app.services.scans import fail_interrupted_runs
from app.services.tools import sync_tool_config
from app.web import Seo, render

log = logging.getLogger("unmask")

STATIC_DIR = Path(__file__).parent / "static"

CSP = "; ".join(
    [
        "default-src 'self'",
        # Every script (htmx, Cytoscape) is self-hosted: analysts' browsers make
        # no third-party requests while working a case.
        "script-src 'self'",
        # The hash allows exactly the one fixed <style> block Cytoscape 3.30.4
        # injects for its container; re-check it when upgrading Cytoscape.
        "style-src 'self' 'sha256-pgvDUBa4IjFA2yuSJ2cqcyxmNYJMborsd0ORcRv9vw8='",
        # Dynamic widths (confidence bars) only; no inline <style> blocks.
        "style-src-attr 'unsafe-inline'",
        "font-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.validate_for_startup()
    cipher.configure(settings.data_keys, settings.index_key)
    async with sessionmaker()() as session:
        await sync_tool_config(session)
        await ensure_admin_user(session)
        if settings.queue_backend == "rq":
            # Workers own running scans; only reap ones far past the job timeout.
            grace = timedelta(seconds=settings.scan_job_timeout_seconds + 600)
            interrupted = await fail_interrupted_runs(session, older_than=grace)
        else:
            interrupted = await fail_interrupted_runs(session)
        if interrupted:
            log.warning("marked %d interrupted scan run(s) as failed", interrupted)
    scheduler = None
    if settings.scheduler_enabled and settings.queue_backend != "rq":
        # With RQ the worker runs the scheduler; inline, the web process does.
        from app.scheduler import run_forever

        scheduler = asyncio.create_task(run_forever(), name="unmask-scheduler")
    yield
    if scheduler is not None:
        scheduler.cancel()
    await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="unmask", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="unmask_session",
        max_age=settings.session_max_age_seconds,
        same_site="lax",
        https_only=settings.is_production,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("Content-Security-Policy", CSP)
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "DENY")
        # Outbound search links must not leak case URLs to third parties.
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if settings.is_production:
            h.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        path = request.url.path
        public = path in ("/", "/robots.txt", "/sitemap.xml", "/site.webmanifest") or path.startswith("/static/")
        if not public or request.session.get("user_id"):
            h.setdefault("X-Robots-Tag", "noindex, nofollow, noarchive")
            h.setdefault("Cache-Control", "no-store")
        return response

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, exc: LoginRequired):
        if request.headers.get("hx-request") == "true":
            return RedirectResponse("/login", status_code=303, headers={"HX-Redirect": "/login"})
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    @app.exception_handler(HTTPException)
    async def _http_error(request: Request, exc: HTTPException):
        if request.headers.get("hx-request") == "true" or not request.headers.get("accept", "").startswith("text/html"):
            return PlainTextResponse(str(exc.detail), status_code=exc.status_code)
        return render(
            request,
            "error.html",
            {"seo": Seo(title=f"Error {exc.status_code}"), "status": exc.status_code, "detail": exc.detail},
            status_code=exc.status_code,
        )

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(public.router)
    app.include_router(auth.router)
    app.include_router(watch.router)  # before cases: /tab/timeline is more specific
    app.include_router(cases.router)
    app.include_router(correlation.router)
    app.include_router(pivots.router)
    app.include_router(settings_routes.router)
    return app


app = create_app()
