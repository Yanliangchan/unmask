"""WhatsMyName: is a username registered on ~650 sites, checked natively from the community dataset.

The WhatsMyName project (github.com/WebBreacher/WhatsMyName, CC BY-SA 4.0) maintains
only data: for each site, the URL to request and what a page looks like when the
account exists (``e_code`` + ``e_string``) and when it doesn't (``m_code`` +
``m_string``). A copy is vendored in ``app/adapters/data/wmn-data.json`` (see
``WMN_COMMIT``) so a scan never fetches checker definitions from the internet.

The site list is maintained separately from Sherlock's and Maigret's, so a profile
that two of them report is corroborated by independent checks.

Every site gets one of three answers: found, missing, or *unclear* (a status or page
that matches neither signature: a bot wall, a rate limit, a changed site). Unclear is
never read as "not found"; if too many sites are unclear the run is refused.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from urllib.parse import quote, urlparse

import httpx

from app.adapters import http
from app.adapters.base import (
    AdapterError,
    EntityCandidate,
    HealthResult,
    RawResult,
    SignatureMismatch,
    ToolAdapter,
)
from app.adapters.lookups import validate_handle
from app.config import get_settings

DATA = Path(__file__).resolve().parent / "data" / "wmn-data.json"
WMN_COMMIT = "038ec49be5d48dd98a33b00d98dbda682c385938"
# Never checked: explicit content, and sites the project marks as archived (gone).
SKIP_CATEGORIES = {"xx NSFW xx", "archived"}
# The focused list: mainstream categories, without sites behind bot protection.
FOCUSED_CATEGORIES = {"social", "coding", "tech", "art", "music", "images", "blog", "video", "business", "gaming"}
MAX_BODY = 400_000
CONCURRENCY = 24
SITE_TIMEOUT = 12.0
# More unclear answers than this and an empty result would mostly be blindness.
MAX_UNCLEAR_RATIO = 0.4
HEALTH_SITES = ("GitHub (User)", "GitLab", "Keybase", "lichess.org")


@cache
def sites() -> list[dict]:
    data = json.loads(DATA.read_text(encoding="utf-8"))
    return [s for s in data["sites"] if s.get("cat") not in SKIP_CATEGORIES and s.get("valid", True) is not False]


def selected(focused: bool) -> list[dict]:
    if not focused:
        return sites()
    return [s for s in sites() if s.get("cat") in FOCUSED_CATEGORIES and not s.get("protection")]


@dataclass
class WmnReport:
    username: str
    found: dict[str, str] = field(default_factory=dict)  # site -> profile URL
    categories: dict[str, str] = field(default_factory=dict)
    missing: int = 0
    unclear: dict[str, str] = field(default_factory=dict)  # site -> why
    checked: int = 0


def _account(site: dict, username: str) -> str:
    for ch in site.get("strip_bad_char") or "":
        username = username.replace(ch, "")
    return quote(username, safe="")


def classify(site: dict, status: int, body: str) -> str:
    """found | missing | unclear, by the site's own signatures."""
    if status == site["e_code"] and site["e_string"] in body:
        return "found"
    if status == site["m_code"] and (not site["m_string"] or site["m_string"] in body):
        return "missing"
    return "unclear"


async def _check(c: httpx.AsyncClient, site: dict, username: str) -> tuple[str, str, str]:
    """(site name, verdict, profile URL or reason)."""
    account = _account(site, username)
    url = site["uri_check"].replace("{account}", account)
    pretty = (site.get("uri_pretty") or site["uri_check"]).replace("{account}", account)
    headers = dict(site.get("headers") or {})
    try:
        if site.get("post_body"):
            resp = await c.post(url, content=site["post_body"].replace("{account}", account), headers=headers)
        else:
            resp = await c.get(url, headers=headers)
        body = resp.content[:MAX_BODY].decode(resp.encoding or "utf-8", "replace")
    except httpx.HTTPError as exc:
        return site["name"], "unclear", exc.__class__.__name__
    verdict = classify(site, resp.status_code, body)
    return site["name"], verdict, pretty if verdict == "found" else f"HTTP {resp.status_code}"


def _client() -> httpx.AsyncClient:
    from app.proxy import proxy_for

    return httpx.AsyncClient(
        transport=http.transport,
        proxy=None if http.transport else proxy_for("whatsmyname"),
        timeout=SITE_TIMEOUT,
        follow_redirects=False,  # the signatures were written against the first response
        headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
                 "Accept-Language": "en-GB,en;q=0.8"},
        limits=httpx.Limits(max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY),
    )  # fmt: skip


async def check_username(username: str, site_list: list[dict]) -> WmnReport:
    report = WmnReport(username=username)
    gate = asyncio.Semaphore(CONCURRENCY)

    async def one(c: httpx.AsyncClient, s: dict):
        async with gate:
            return await _check(c, s, username)

    async with _client() as c:
        results = await asyncio.gather(*(one(c, s) for s in site_list))
    cats = {s["name"]: s.get("cat", "") for s in site_list}
    for name, verdict, detail in results:
        report.checked += 1
        if verdict == "found":
            report.found[name] = detail
            report.categories[name] = cats[name]
        elif verdict == "missing":
            report.missing += 1
        else:
            report.unclear[name] = detail
    return report


class WhatsMyNameAdapter(ToolAdapter):
    name = "whatsmyname"
    label = "WhatsMyName"
    input_types = ["username"]
    description = (
        "Checks a username on about 650 sites using the WhatsMyName community dataset: a site list maintained "
        "separately from Sherlock's and Maigret's, so agreement between them is independent."
    )
    health_check_target = "torvalds"
    verify_accounts = True
    timeout_seconds = 240

    def focused(self) -> bool:
        return get_settings().username_sites == "focused"

    async def run(self, target_value: str, context_tags: list[str], only: tuple[str, ...] = ()) -> list[RawResult]:
        username = validate_handle(target_value)
        site_list = [s for s in sites() if s["name"] in only] if only else selected(self.focused())
        if not site_list:
            raise AdapterError("no WhatsMyName sites selected")
        report = await check_username(username, site_list)
        if report.checked and len(report.unclear) / report.checked > MAX_UNCLEAR_RATIO and not only:
            raise SignatureMismatch(
                f"{len(report.unclear)} of {report.checked} sites gave no clear answer (blocked, rate-limited or "
                "changed); an empty result would not mean the username is unused"
            )
        return [RawResult(self.name, username, report)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        r: WmnReport = raw.payload
        return [
            EntityCandidate(
                type="account",
                value=url,
                attributes={
                    "site": site,
                    "username": r.username,
                    "url": url,
                    "host": urlparse(url).hostname,
                    "category": r.categories.get(site) or None,
                },  # fmt: skip
                # The same presence-check method as Sherlock, from an independently kept list.
                source_reliability="C",
                confidence=0.4,
                field_confidence={"exists": 0.7, "same_person": 0.4},
                relation_type="has_account",
                relation_explanation=f"username '{r.username}' registered on {site} (WhatsMyName)",
            )
            for site, url in sorted(r.found.items())
        ]

    async def health_check(self) -> HealthResult:
        try:
            raws = await self.run(self.health_check_target, [], only=HEALTH_SITES)
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        r: WmnReport = raws[0].payload
        if not r.found:
            return HealthResult(False, f"known account not found on {', '.join(HEALTH_SITES)}")
        total = len(selected(self.focused()))
        return HealthResult(True, f"known account found on {', '.join(sorted(r.found))}; {total} sites in the list")
