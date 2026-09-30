"""Public, crawlable surface: landing page, robots.txt, sitemap, manifest, health."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app import brand
from app.config import get_settings
from app.db import get_session
from app.security import current_user_optional
from app.web import SITE_DESCRIPTION, TEMPLATES_DIR, Seo, render

router = APIRouter()

# Paths that may appear in search results. Everything else is private.
PUBLIC_PATHS = ["/", "/trust", "/terms", "/acceptable-use", "/privacy"]
LANDING_TEMPLATE = TEMPLATES_DIR / "public" / "landing.html"


def available_tool_labels() -> list[str]:
    """Tools this deployment can actually run: the landing page only advertises those."""
    from app.adapters.registry import all_adapters

    return [a.label for a in all_adapters() if a.configured() is None]


def _tool_sentence(labels: list[str]) -> str:
    if not labels:
        return "open-source OSINT tools"
    if len(labels) > 8:
        return ", ".join(labels[:8]) + f" and {len(labels) - 8} more tools"
    return labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]


FAQ = [
    ("What is UNMASK?",
     "A self-hosted open-source intelligence (OSINT) platform. You add what you know about a person or organisation "
     "(a username, email address, name, domain, phone number or IP address), and UNMASK runs a set of OSINT tools as "
     "one case, then de-duplicates, scores and links what they find."),
    ("Which tools does it run?",
     "Username checkers such as Sherlock and Maigret, direct lookups against GitHub, GitLab, Keybase, Hacker News and "
     "Gravatar, breach sources, web search, certificate transparency, DNS and domain registration records, and more. "
     "Tools that need an API key are added from the Integrations page."),
    ("How does it cut false positives?",
     "Every account hit is checked against its profile page before it is shown, profiles are compared on names, "
     "locations and links, common usernames are scored down, and your own decisions teach it which sites to trust. "
     "Scores come with the reasons behind them."),
    ("Is my data safe?",
     "UNMASK is self-hosted, so case data stays on your infrastructure. Identifiers are encrypted at rest, every "
     "decision and export is audited, and cases are deleted when their retention period ends."),
    ("Can I use it on anyone?",
     "No. Every case needs a documented lawful basis and authorisation, and the Acceptable Use Policy prohibits "
     "stalking, harassment and discrimination. You are responsible for how you use it."),
    ("What do I get at the end?",
     "A report built around your written assessment, with the evidence behind it, plus CSV, JSON and STIX 2.1 exports "
     "and read-only links that expire."),
]  # fmt: skip


def landing_seo() -> Seo:
    base = get_settings().public_base_url.rstrip("/")
    return Seo(
        title=f"{brand.NAME}: {brand.DESCRIPTOR} | {brand.TAGLINE}",
        description=SITE_DESCRIPTION,
        path="/",
        indexable=True,
        json_ld=[
            {
                "@context": "https://schema.org",
                "@type": "SoftwareApplication",
                "name": brand.NAME,
                "applicationCategory": "SecurityApplication",
                "operatingSystem": "Linux, Docker",
                "description": SITE_DESCRIPTION,
                "url": base + "/",
                "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
                "screenshot": base + "/static/img/screenshot-case.png",
                "image": base + "/static/img/og-image.png",
                "featureList": [
                    f"Runs {_tool_sentence(available_tool_labels())} as one case",
                    "De-duplicated findings with per-field confidence and source reliability",
                    "Automatic follow-up lookups, each one logged",
                    "Scan-to-scan comparison with watch mode",
                    "Tool failures reported instead of shown as empty results",
                    "Self-hosted, with identifiers encrypted at rest",
                ],
            },
            {
                "@context": "https://schema.org",
                "@type": "FAQPage",
                "mainEntity": [
                    {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a}} for q, a in FAQ
                ],
            },
            {
                "@context": "https://schema.org",
                "@type": "WebSite",
                "name": brand.NAME,
                "url": base + "/",
            },
        ],
    )


def render_landing(request: Request):
    labels = available_tool_labels()
    return render(
        request,
        "public/landing.html",
        {"seo": landing_seo(), "tools_sentence": _tool_sentence(labels), "tool_labels": labels, "faq": FAQ},
    )


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
            "name": brand.NAME,
            "short_name": brand.NAME,
            "description": SITE_DESCRIPTION,
            "start_url": "/",
            "display": "standalone",
            "background_color": brand.THEME_DARK,
            "theme_color": brand.THEME_DARK,
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
               "How UNMASK protects the data in your investigations, what leaves the platform, and who is "
               "responsible for what."),
    "/terms": ("terms.html", "Terms of Service",
               "The terms that govern use of UNMASK, including your responsibilities for lawful, authorised "
               "investigations."),
    "/acceptable-use": ("acceptable_use.html", "Acceptable Use Policy", "What UNMASK may and may never be used for."),
    "/privacy": ("privacy.html", "Privacy Notice",
                 "How personal data is handled in running UNMASK, for users and for people who are researched."),
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
