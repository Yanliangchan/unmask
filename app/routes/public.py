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


# Infrastructure first: most cases start from an organisation, not a person.
INPUT_LABELS = {"domain": "Domains", "ip": "IP addresses", "email": "Email addresses", "username": "Usernames",
                "name": "Names", "phone": "Phone numbers"}  # fmt: skip


def tool_groups() -> list[tuple[str, list[str]]]:
    """What this deployment can look up, by what you give it."""
    from app.adapters.registry import all_adapters

    groups: dict[str, list[str]] = {k: [] for k in INPUT_LABELS}
    for a in all_adapters():
        if a.configured() is not None:
            continue
        for t in a.input_types:
            if t in groups and a.label not in groups[t]:
                groups[t].append(a.label)
    return [(INPUT_LABELS[k], sorted(v)) for k, v in groups.items() if v]


def _tool_sentence(labels: list[str]) -> str:
    if not labels:
        return "open-source OSINT tools"
    if len(labels) > 8:
        return ", ".join(labels[:8]) + f" and {len(labels) - 8} more tools"
    return labels[0] if len(labels) == 1 else ", ".join(labels[:-1]) + " and " + labels[-1]


FAQ = [
    ("What is UNMASK?",
     "An open-source, self-hosted case platform for authorised OSINT investigations. You open a case with a written "
     "authorisation, UNMASK runs your OSINT tools as one case, and you get de-duplicated findings scored with their "
     "reasons, a graph of how they connect, and a report built around your conclusion."),
    ("Is it really open source?",
     "Yes, under the MIT licence. You run it on your own servers with Docker, Postgres and Redis. The OSINT tools it "
     "runs keep their own licences and run as separate programs."),
    ("Where does case data live?",
     "On your infrastructure. Identifiers and notes are encrypted at rest with keys kept apart from the database, "
     "there is no telemetry, and each case is deleted when its retention period ends. The audit log is kept."),
    ("What leaves my network?",
     "Only the lookups themselves: the identifiers in a case are sent to the sources that check them. Which sources "
     "run is listed on the Tools page, and tools that need an API key stay off until you add one."),
    ("Does a high score mean it is the same person?",
     "No. A score says how much the collected evidence ties a finding to the subject, and lists what raised and "
     "lowered it. Inferred links are marked as inferred, and only a person can confirm a finding."),
    ("How is misuse prevented?",
     "Every case needs a written authorisation and a lawful basis, enforced down to a database constraint. A case "
     "holds at most 25 identifiers, each account has daily limits, every action is logged against a named person, "
     "and reports can't leave without a written assessment."),
    ("What can I hand over at the end?",
     "A report in PDF, Word, HTML or Markdown, marked TLP:AMBER with a reference on every page; an evidence bundle "
     "with a SHA-256 manifest; CSV, JSON and STIX 2.1 data; and read-only links that expire. There is also an API "
     "and signed webhooks."),
    ("How accurate is it?",
     "The matching engine is measured on every change against labelled synthetic cases built around the ways "
     "attribution goes wrong, and the results are reproducible with one command. Synthetic cases test the logic, not "
     "the world, which is why a person makes every call."),
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
                "offers": {"@type": "Offer", "price": "0", "priceCurrency": "GBP"},
                "license": "https://opensource.org/licenses/MIT",
                "isAccessibleForFree": True,
                "codeRepository": brand.SOURCE_URL,
                "screenshot": base + "/static/img/landing/graph-light-1200.webp",
                "image": base + "/static/img/og-image.png",
                "featureList": [
                    f"Runs {_tool_sentence(available_tool_labels())} as one case",
                    "De-duplicated findings with per-field confidence and source reliability",
                    "Automatic follow-up lookups, each one logged",
                    "Scan-to-scan comparison with watch mode",
                    "Tool failures reported instead of shown as empty results",
                    "Self-hosted, with identifiers encrypted at rest",
                    "Reports in PDF, Word, HTML and Markdown, and evidence bundles with a SHA-256 manifest",
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
        {
            "seo": landing_seo(),
            "tools_sentence": _tool_sentence(labels),
            "tool_labels": labels,
            "faq": FAQ,
            "tool_groups": tool_groups(),
            "source_count": len(labels),
        },
    )


@router.get("/favicon.ico", include_in_schema=False)
async def favicon():
    # Browsers ask for /favicon.ico on pages that don't name an icon (raw files, JSON).
    from fastapi.responses import RedirectResponse

    from app.web import static_url

    return RedirectResponse(static_url("img/favicon.svg"), status_code=301)


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
