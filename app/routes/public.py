"""Public, crawlable surface: landing page, robots.txt, sitemap, manifest, health."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db import get_session
from app.security import current_user_optional
from app.web import SITE_DESCRIPTION, TEMPLATES_DIR, Seo, render

router = APIRouter()

# Paths that may appear in search results. Everything else is private.
PUBLIC_PATHS = ["/", "/trust", "/terms", "/acceptable-use", "/privacy"]
LANDING_TEMPLATE = TEMPLATES_DIR / "public" / "landing.html"


def landing_seo() -> Seo:
    base = get_settings().public_base_url.rstrip("/")
    return Seo(
        title="unmask: self-hosted OSINT investigation platform",
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
                "screenshot": base + "/static/img/screenshot-case.png",
                "image": base + "/static/img/og-image.png",
                "featureList": [
                    "Runs Sherlock, Maigret, Holehe, theHarvester, crt.sh, Amass and SpiderFoot as one case",
                    "De-duplicated findings with per-field confidence and source reliability",
                    "Automatic follow-up lookups, each one logged",
                    "Scan-to-scan comparison with watch mode",
                    "Tool failures reported instead of shown as empty results",
                    "Self-hosted, with identifiers encrypted at rest",
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
        "Allow: /trust\n"
        "Allow: /terms\n"
        "Allow: /acceptable-use\n"
        "Allow: /privacy\n"
        "Disallow: /cases\n"
        "Disallow: /login\n"
        "Disallow: /partials\n"
        "Disallow: /tools\n"
        f"\nSitemap: {base}/sitemap.xml\n"
    )


@router.get("/sitemap.xml", include_in_schema=False)
async def sitemap() -> Response:
    base = get_settings().public_base_url.rstrip("/")
    lastmod = datetime.fromtimestamp(LANDING_TEMPLATE.stat().st_mtime, UTC).date().isoformat()
    urls = "".join(
        f"<url><loc>{base}{path}</loc><lastmod>{lastmod}</lastmod><changefreq>monthly</changefreq></url>"
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
            "background_color": "#0e0f11",
            "theme_color": "#0e0f11",
            "icons": [
                {"src": "/static/img/favicon.svg", "sizes": "any", "type": "image/svg+xml"},
                {"src": "/static/img/icon-192.png", "sizes": "192x192", "type": "image/png"},
                {"src": "/static/img/icon-512.png", "sizes": "512x512", "type": "image/png"},
            ],
        },
        media_type="application/manifest+json",
    )


@router.get("/healthz", include_in_schema=False)
async def healthz(session: AsyncSession = Depends(get_session)) -> JSONResponse:
    await session.execute(text("SELECT 1"))
    return JSONResponse({"status": "ok"})


# --- Legal and trust pages ----------------------------------------------------------------------

LEGAL = {
    "/trust": ("trust.html", "Trust",
               "How unmask protects the data in your investigations, what leaves the platform, and who is "
               "responsible for what."),
    "/terms": ("terms.html", "Terms of Service",
               "The terms that govern use of unmask, including your responsibilities for lawful, authorised "
               "investigations."),
    "/acceptable-use": ("acceptable_use.html", "Acceptable Use Policy", "What unmask may and may never be used for."),
    "/privacy": ("privacy.html", "Privacy Notice",
                 "How personal data is handled in running unmask, for users and for people who are researched."),
}  # fmt: skip


def legal_context(path: str) -> dict:
    from app.legal import PAGES, details

    _, title, description = LEGAL[path]
    return {
        "seo": Seo(title=title, description=description, path=path, indexable=True),
        "L": details(),
        "legal_pages": PAGES,
    }


def _legal_page(path: str):
    async def page(request: Request, user=Depends(current_user_optional)):
        return render(request, f"public/legal/{LEGAL[path][0]}", {**legal_context(path), "user": user})

    return page


for _path in LEGAL:
    router.add_api_route(_path, _legal_page(_path), methods=["GET", "HEAD"], include_in_schema=False)


@router.get("/.well-known/security.txt", response_class=PlainTextResponse, include_in_schema=False)
async def security_txt() -> Response:
    from datetime import timedelta

    from app.legal import details

    contact = details().security_contact
    if not contact:
        return PlainTextResponse("", status_code=404)
    base = get_settings().public_base_url.rstrip("/")
    expires = (datetime.now(UTC) + timedelta(days=180)).strftime("%Y-%m-%dT00:00:00Z")
    return PlainTextResponse(
        f"Contact: mailto:{contact}\nExpires: {expires}\nPolicy: {base}/trust#disclosure\n"
        f"Preferred-Languages: en\nCanonical: {base}/.well-known/security.txt\n"
    )
