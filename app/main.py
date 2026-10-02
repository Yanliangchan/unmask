from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import timedelta
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException
from starlette.middleware.gzip import DEFAULT_EXCLUDED_CONTENT_TYPES, GZipMiddleware
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.crypto import cipher
from app.db import dispose_engine, sessionmaker
from app.routes import (
    auth,
    cases,
    correlation,
    evidence,
    inbox,
    integrations,
    pivots,
    public,
    review,
    search,
    watch,
    web_tab,
    workspace,
)
from app.routes import settings as settings_routes
from app.security import LoginRequired, TermsRequired, ensure_admin_user
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


_NO_KEYS_PATHS = frozenset({"/healthz", "/notifications/badge", "/robots.txt", "/favicon.ico"})


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    settings.validate_for_startup()
    cipher.configure(settings.data_keys, settings.index_key)
    async with sessionmaker()() as session:
        from app.integrations import refresh as refresh_integrations

        await refresh_integrations(session, force=True)
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
    from app import idle
    from app.memory import trim

    scheduler = None
    if settings.scheduler_enabled and settings.queue_backend != "rq":
        # With RQ the worker runs the scheduler; inline, the web process does.
        from app.scheduler import run_forever as scheduler
    # The idle monitor owns the scheduler loop: it stops it (and closes database
    # connections) when nobody is using the app, and restarts it on the next request.
    idle.monitor = idle.IdleMonitor(settings.idle_seconds, scheduler) if settings.idle_seconds > 0 else None
    if idle.monitor is not None:
        idle.monitor.start()
    elif scheduler is not None:
        scheduler_task = asyncio.create_task(scheduler(), name="unmask-scheduler")
    trim()  # startup work (migrations check, config sync) leaves garbage behind
    yield
    if idle.monitor is not None:
        await idle.monitor.stop()
        idle.monitor = None
    elif scheduler is not None:
        scheduler_task.cancel()
    await idle.close_network()
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
    async def integration_keys(request: Request, call_next):
        # Keys entered in another process (or another replica) reach this one within a minute.
        # Static files, health checks and the badge poll never need them.
        path = request.url.path
        if not (path.startswith("/static") or path in _NO_KEYS_PATHS):
            from app.integrations import refresh as refresh_integrations

            await refresh_integrations()
        return await call_next(request)

    @app.middleware("http")
    async def idle_tracking(request: Request, call_next):
        from app import idle

        mon = idle.monitor
        if mon is None:
            return await call_next(request)
        mon.request_started()
        try:
            return await call_next(request)
        finally:
            mon.request_finished()

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
        if path.startswith("/static/") and response.status_code == 200:
            # Templates link static files with a content hash (?v=...), so a
            # changed file always gets a new URL and old ones never go stale.
            if "v" in request.query_params:
                h.setdefault("Cache-Control", "public, max-age=31536000, immutable")
            else:
                h.setdefault("Cache-Control", "public, max-age=3600")
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

    @app.exception_handler(TermsRequired)
    async def _terms_required(request: Request, exc: TermsRequired):
        target = "/legal/accept"
        if request.method == "GET" and request.url.path != "/":
            target += f"?next={request.url.path}"
        if request.headers.get("hx-request") == "true":
            return RedirectResponse(target, status_code=303, headers={"HX-Redirect": target})
        return RedirectResponse(target, status_code=303)

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

    # Compress static text only. HTML pages carry CSRF tokens next to user input,
    # so they stay uncompressed (BREACH).
    static = GZipMiddleware(
        StaticFiles(directory=str(STATIC_DIR)),
        minimum_size=1024,
        exclude_content_types=(*DEFAULT_EXCLUDED_CONTENT_TYPES, "image/png", "image/webp", "image/jpeg"),
    )
    app.mount("/static", static, name="static")
    app.include_router(public.router)
    app.include_router(auth.router)
    app.include_router(watch.router)  # before cases: /tab/timeline is more specific
    app.include_router(cases.router)
    app.include_router(correlation.router)
    app.include_router(pivots.router)
    app.include_router(settings_routes.router)
    app.include_router(web_tab.router)
    app.include_router(review.router)
    app.include_router(search.router)
    app.include_router(workspace.router)
    app.include_router(inbox.router)
    app.include_router(evidence.router)
    app.include_router(integrations.router)
    return app


app = create_app()
