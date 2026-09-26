"""Public, crawlable surface: landing page, robots.txt, sitemap, manifest, health."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_session
from app.web import SITE_DESCRIPTION, Seo, render

router = APIRouter()

# Paths that may appear in search results. Everything else is private.
PUBLIC_PATHS = ["/"]


def landing_seo() -> Seo:
    base = get_settings().public_base_url.rstrip("/")
    return Seo(
        title="unmask — self-hosted OSINT investigation platform",
        description=SITE_DESCRIPTION,
        path="/",
        indexable=True,
        json_ld=[
            {
                "@context": "https://schema.org",
                "@type": "SoftwareApplication",
                "name": "unmask",
                "applicationCategory": "SecurityApplication",
                "operatingSystem": "Linux, Docker",
                "description": SITE_DESCRIPTION,
                "url": base + "/",
                "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
                "featureList": [
                    "Automated pivot chains with a visible pivot log",
                    "Case management with a full audit trail",
                    "Time-aware diffing between scan runs",
                    "Open tool-adapter plugin architecture",
                    "Per-field confidence and source reliability ratings",
                    "Encryption at rest for sensitive identifiers",
                ],
            },
            {
                "@context": "https://schema.org",
                "@type": "WebSite",
                "name": "unmask",
                "url": base + "/",
            },
        ],
    )


def render_landing(request: Request):
    return render(request, "public/landing.html", {"seo": landing_seo()})


@router.get("/robots.txt", response_class=PlainTextResponse, include_in_schema=False)
async def robots() -> str:
    s = get_settings()
    base = s.public_base_url.rstrip("/")
    if not s.allow_indexing:
        return "User-agent: *\nDisallow: /\n"
    return (
        "User-agent: *\n"
        "Allow: /$\n"
        "Allow: /static/\n"
        "Disallow: /cases\n"
        "Disallow: /login\n"
        "Disallow: /partials\n"
        "Disallow: /tools\n"
        f"\nSitemap: {base}/sitemap.xml\n"
    )


@router.get("/sitemap.xml", include_in_schema=False)
async def sitemap() -> Response:
    base = get_settings().public_base_url.rstrip("/")
    urls = "".join(
        f"<url><loc>{base}{path}</loc><changefreq>monthly</changefreq><priority>1.0</priority></url>"
        for path in PUBLIC_PATHS
    )
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{urls}</urlset>'
    )
    return Response(xml, media_type="application/xml")


@router.get("/site.webmanifest", include_in_schema=False)
async def manifest() -> JSONResponse:
    return JSONResponse(
        {
            "name": "unmask",
            "short_name": "unmask",
            "description": SITE_DESCRIPTION,
            "start_url": "/",
            "display": "standalone",
            "background_color": "#0b0e13",
            "theme_color": "#0b0e13",
            "icons": [{"src": "/static/img/favicon.svg", "sizes": "any", "type": "image/svg+xml"}],
        },
        media_type="application/manifest+json",
    )


@router.get("/healthz", include_in_schema=False)
async def healthz(session: AsyncSession = Depends(get_session)) -> JSONResponse:
    await session.execute(text("SELECT 1"))
    return JSONResponse({"status": "ok"})
