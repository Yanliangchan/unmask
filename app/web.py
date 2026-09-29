"""Template rendering and per-page SEO metadata."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from markupsafe import Markup, escape

from app.config import get_settings
from app.models import SOURCE_RELIABILITY
from app.search_links import search_links
from app.security import csrf_token

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

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


THEMES = ("system", "light", "dark")


@lru_cache(maxsize=256)
def _static_digest(path: str, mtime_ns: int) -> str:
    return hashlib.sha256((STATIC_DIR / path).read_bytes()).hexdigest()[:10]


def static_url(path: str) -> str:
    """URL for a static file with a content hash, so browsers can cache it for a year.

    The mtime is part of the cache key, so an edited file gets a new hash
    without restarting the server.
    """
    try:
        digest = _static_digest(path, (STATIC_DIR / path).stat().st_mtime_ns)
    except OSError:
        return f"/static/{path}"
    return f"/static/{path}?v={digest}"


def render(
    request: Request,
    template: str,
    context: dict[str, Any] | None = None,
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
):
    ctx = {
        "request": request,
        "csrf_token": csrf_token(request),
        "settings": get_settings(),
        "now": datetime.now(UTC),
    }
    ctx.update(context or {})
    ctx.setdefault("seo", Seo(title="unmask"))
    ctx.setdefault("user", None)
    # The theme is rendered server-side from a cookie so pages never flash the wrong one.
    theme = request.cookies.get("theme")
    ctx.setdefault("theme", theme if theme in THEMES else "system")
    return templates.TemplateResponse(request, template, ctx, status_code=status_code, headers=headers)


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
    "_cancelled": "stopped",
}


def _run_issues(details: dict | None) -> dict:
    """Split a run's failure_details into per-tool failures and run-level issues (notes excluded)."""
    tools, other = [], []
    for key, value in sorted((details or {}).items()):
        if key in ("_correlation", "_pivots", "_verification"):
            continue
        if key.startswith("_"):
            other.append((RUN_NOTE_LABELS.get(key, key.lstrip("_")), value))
        else:
            tools.append((key, value))
    return {"tools": tools, "other": other}


templates.env.filters["run_issues"] = _run_issues
templates.env.globals["SOURCE_RELIABILITY"] = SOURCE_RELIABILITY
templates.env.globals["search_links"] = search_links
templates.env.globals["static_url"] = static_url


def _tool_label(name: str) -> str:
    from app.adapters.registry import get_adapter

    adapter = get_adapter(name)
    return adapter.label if adapter else name


templates.env.globals["tool_label"] = _tool_label
templates.env.filters["tool_label"] = _tool_label


def _explain_failure(tool: str, error: str):
    from app.services.failures import explain

    return explain(tool, error)


templates.env.globals["explain_failure"] = _explain_failure

_MENTION_RE = re.compile(r"@([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})")


def _mentions(text: str) -> Markup:
    """Escape a note, then highlight @mentions. Nothing the user typed is rendered as HTML."""
    safe = str(escape(text or ""))
    return Markup(_MENTION_RE.sub(r'<span class="mention">@\1</span>', safe))  # noqa: S704 — input escaped above


templates.env.filters["mentions"] = _mentions


def _strength(entity) -> tuple[str, str]:
    """Plain-language match strength; the numeric score stays in tooltips and details."""
    from app.services.entities import LIKELY, POSSIBLE

    if entity.is_seed:
        return "target", "Target"
    if entity.dismissed_flag:
        return "dismissed", "Not them"
    if entity.confirmed_flag:
        return "confirmed", "Confirmed"
    if entity.confidence >= LIKELY:
        return "likely", "Likely"
    if entity.confidence >= POSSIBLE:
        return "possible", "Possible"
    return "unlikely", "Unlikely"


templates.env.filters["strength"] = _strength
templates.env.filters["case_tags"] = lambda case: sorted(
    {t for target in (case.targets or []) for t in (target.context_tags or [])}
)
