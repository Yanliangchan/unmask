"""Template rendering and per-page SEO metadata."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from markupsafe import Markup

from app.config import get_settings
from app.models import SOURCE_RELIABILITY
from app.search_links import search_links
from app.security import csrf_token

TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

SITE_DESCRIPTION = (
    "unmask is a self-hosted OSINT platform that runs your research tools as a case: findings are "
    "de-duplicated, scored, linked and compared between scans, with every automatic step logged."
)


@dataclass
class Seo:
    title: str
    description: str = SITE_DESCRIPTION
    path: str = "/"
    # Everything behind the login is private case data and must never be indexed.
    indexable: bool = False
    og_type: str = "website"
    json_ld: list[dict[str, Any]] = field(default_factory=list)

    @property
    def full_title(self) -> str:
        return self.title if self.title.startswith("unmask") else f"{self.title} · unmask"

    @property
    def canonical(self) -> str:
        return get_settings().public_base_url.rstrip("/") + self.path

    @property
    def robots(self) -> str:
        if self.indexable and get_settings().allow_indexing:
            return "index, follow, max-image-preview:large"
        return "noindex, nofollow, noarchive"

    @property
    def json_ld_markup(self) -> Markup:
        blocks = [
            '<script type="application/ld+json">'
            + json.dumps(block, separators=(",", ":")).replace("<", "\\u003c")
            + "</script>"
            for block in self.json_ld
        ]
        # Safe: json.dumps output with every "<" escaped cannot close the script tag.
        return Markup("\n".join(blocks))  # noqa: S704


def render(request: Request, template: str, context: dict[str, Any] | None = None, *, status_code: int = 200):
    ctx = {
        "request": request,
        "csrf_token": csrf_token(request),
        "settings": get_settings(),
        "now": datetime.now(UTC),
    }
    ctx.update(context or {})
    ctx.setdefault("seo", Seo(title="unmask"))
    ctx.setdefault("user", None)
    return templates.TemplateResponse(request, template, ctx, status_code=status_code)


def _timeago(value: datetime | None) -> str:
    if value is None:
        return "never"
    delta = datetime.now(UTC) - value
    secs = int(delta.total_seconds())
    if secs < 60:
        return "just now"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return "just now"


def _isodate(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if value else "—"


def _confidence_tier(value: float | None) -> str:
    if value is None:
        return "unknown"
    if value >= 0.75:
        return "high"
    if value >= 0.45:
        return "medium"
    return "low"


templates.env.filters["timeago"] = _timeago
templates.env.filters["isodate"] = _isodate
templates.env.filters["confidence_tier"] = _confidence_tier
templates.env.filters["tojson_pretty"] = lambda v: json.dumps(v, indent=2, sort_keys=True, default=str)
templates.env.filters["display_fields"] = lambda fc: sorted(
    (k, v) for k, v in (fc or {}).items() if not k.startswith("evidence.") and k != "prior"
)
templates.env.filters["public_attributes"] = lambda attrs: {
    k: v for k, v in (attrs or {}).items() if not str(k).startswith("_")
}
RUN_NOTE_LABELS = {
    "_skipped": "skipped",
    "_none": "no tools",
    "_interrupted": "interrupted",
    "_crashed": "crashed",
    "_correlation_error": "matching",
    "_pivots_error": "pivots",
}


def _run_issues(details: dict | None) -> dict:
    """Split a run's failure_details into per-tool failures and run-level issues (notes excluded)."""
    tools, other = [], []
    for key, value in sorted((details or {}).items()):
        if key in ("_correlation", "_pivots"):
            continue
        if key.startswith("_"):
            other.append((RUN_NOTE_LABELS.get(key, key.lstrip("_")), value))
        else:
            tools.append((key, value))
    return {"tools": tools, "other": other}


templates.env.filters["run_issues"] = _run_issues
templates.env.globals["SOURCE_RELIABILITY"] = SOURCE_RELIABILITY
templates.env.globals["search_links"] = search_links
templates.env.filters["case_tags"] = lambda case: sorted(
    {t for target in (case.targets or []) for t in (target.context_tags or [])}
)
