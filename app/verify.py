"""Profile-page verification for account hits.

Username checkers (Sherlock, Maigret) decide "account exists" from a status
code or a phrase on the page. From a cloud IP many sites answer with a login
wall, a bot check or a soft "user not found" page instead, and those read as
hits. Before an account is shown, its page is fetched once and classified:

* ``verified``   the page is up and names the username in its title or
                 profile metadata;
* ``unverified`` the page could not be judged (bot wall, login wall, timeout,
                 or the username only appears in the page source);
* ``rejected``   the page itself says the profile does not exist, or it
                 redirects to a login or home page.

Rejected hits are dropped and counted; unverified ones are kept but weighted
down and hidden from the default view. The page is fetched from the server,
never from the analyst's browser, and preview images are recorded as URLs only.
"""

from __future__ import annotations

import asyncio
import html
import random
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx

from app.adapters.base import EntityCandidate
from app.config import get_settings

VERIFIED, UNVERIFIED, REJECTED = "verified", "unverified", "rejected"

# Tests swap this for an httpx.MockTransport.
transport: httpx.AsyncBaseTransport | None = None

# A current desktop browser: many sites serve a stripped or blocked page to
# anything that looks like a script.
BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.8",
}
# Enough for the head, the profile header and its links; classification reads the first 60 KB.
MAX_BYTES = 200_000
PER_HOST = 2
EXCERPT_CHARS = 280
# Transient answers worth one more try; login walls and "not found" pages never are.
_RETRY_STATUS = {429, 502, 503, 504}
_MAX_RETRY_AFTER = 5.0

_BOT_WALL = re.compile(
    r"just a moment|attention required|cf-browser-verification|cf-chl-|captcha|are you a robot|"
    r"are you a human|verify you are human|access denied|request unsuccessful|ddos-guard|"
    r"checking your browser|unusual traffic|px-block",
    re.I,
)
_NOT_FOUND = re.compile(
    r"page not found|profile not found|user not found|account not found|not be found|"
    r"(?:doesn.t|does not|no longer) exist|isn.t available|is not available|no longer available|"
    r"nothing (?:was )?found|couldn.t find|could not find|can.t find|cannot find|"
    r"account (?:has been )?(?:suspended|deactivated|terminated)|\b404\b|this user has been",
    re.I,
)
_LOGIN = re.compile(r"\b(?:log ?in|sign ?in|sign ?up|create an account|join)\b", re.I)
_LOGIN_PATH = re.compile(r"/(?:login|signin|sign-in|log-in|signup|sign-up|join|register|auth|accounts/login)\b", re.I)

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_META = re.compile(r"<meta\s+[^>]*>", re.I)
_ATTR = re.compile(r'([a-zA-Z:_-]+)\s*=\s*("([^"]*)"|\'([^\']*)\')')
_CANONICAL = re.compile(r'<link\s+[^>]*rel=["\']canonical["\'][^>]*>', re.I)
_HREF = re.compile(r"""<a\s[^>]*?href\s*=\s*["']([^"'#][^"']*)["']""", re.I)
_MAILTO = re.compile(r"mailto:([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24})", re.I)
# Hosts whose links are site furniture (app stores, share buttons, CDNs), never someone's own page.
_BOILERPLATE = re.compile(
    r"(?:^|\.)(?:google|apple|microsoft|mozilla|cloudflare|cloudfront|akamaihd|gstatic|w3\.org|schema\.org|"
    r"creativecommons|gravatar|wikipedia|wikimedia|archive\.org|onetrust|cookielaw|doubleclick|googletagmanager|"
    r"play\.google|itunes|apps\.apple|bit\.ly)(?:\.[a-z.]+)?$",
    re.I,
)
MAX_LINKS = 20
_CHROME = re.compile(r"<(nav|footer)\b[^>]*>.*?</\1\s*>", re.I | re.S)
_TAGS = re.compile(r"<(script|style)[^>]*>.*?</\1>|<[^>]+>", re.I | re.S)


@dataclass
class Verdict:
    status: str
    reason: str
    preview: dict[str, Any] = field(default_factory=dict)


def _fold(text: str) -> str:
    return re.sub(r"[\s._\-]", "", text.casefold())


def _visible_text(page: str) -> str:
    text = _TAGS.sub(" ", _CHROME.sub(" ", page))
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def _loose(term: str) -> re.Pattern | None:
    """A pattern for a handle or name that tolerates separators: jane_doe ~ jane.doe ~ Jane Doe."""
    chars = [c for c in term.casefold() if c.isalnum()]
    if len(chars) < 3:
        return None
    return re.compile(r"[\s._\-]?".join(re.escape(c) for c in chars), re.I)


def excerpt(page_text: str, terms: list[str], width: int = EXCERPT_CHARS) -> str:
    """The stretch of visible text around the first mention of any term, trimmed to whole words."""
    for term in terms:
        pattern = _loose(term)
        m = pattern.search(page_text) if pattern else None
        if not m:
            continue
        start = max(0, m.start() - width // 3)
        end = min(len(page_text), start + width)
        snippet = page_text[start:end]
        if start > 0:
            snippet = "…" + snippet.split(" ", 1)[-1]
        if end < len(page_text):
            snippet = snippet.rsplit(" ", 1)[0] + "…"
        return snippet
    return ""


def _meta(page: str) -> dict[str, str]:
    """og:/twitter:/profile: and description meta tags, first value wins."""
    found: dict[str, str] = {}
    for tag in _META.findall(page[:MAX_BYTES]):
        attrs = {m[0].lower(): html.unescape(m[2] or m[3]) for m in _ATTR.findall(tag)}
        key = attrs.get("property") or attrs.get("name")
        if key and "content" in attrs:
            found.setdefault(key.lower(), attrs["content"].strip())
    return found


def extract_preview(page: str) -> dict[str, str]:
    meta = _meta(page)
    title_m = _TITLE.search(page)
    title = html.unescape(re.sub(r"\s+", " ", title_m.group(1))).strip() if title_m else ""
    canonical = ""
    if m := _CANONICAL.search(page):
        attrs = {a[0].lower(): a[2] or a[3] for a in _ATTR.findall(m.group(0))}
        canonical = attrs.get("href", "")
    preview = {
        "title": meta.get("og:title") or meta.get("twitter:title") or title,
        "page_title": title,
        "description": meta.get("og:description") or meta.get("description") or meta.get("twitter:description") or "",
        "image": meta.get("og:image") or meta.get("twitter:image") or "",
        "username": meta.get("profile:username") or "",
        "canonical": canonical,
    }
    return {k: v[:500] for k, v in preview.items() if v}


def _base_domain(host: str) -> str:
    parts = host.lower().split(".")
    return ".".join(parts[-3:] if len(parts) > 2 and len(parts[-2]) <= 3 else parts[-2:])


def _brand(host: str) -> str:
    """The name part of a site's domain: tryhackme.com -> "tryhackme", app.hackthebox.eu -> "hackthebox"."""
    return _base_domain(host).split(".")[0]


def _norm_handle(handle: str) -> str:
    return re.sub(r"[^a-z0-9]", "", handle.lower())


def is_site_account(handle: str, *hosts: str) -> bool:
    """True if a profile handle is a site's own account rather than a person's.

    Profile pages carry the site's own social links in their header and footer
    (TryHackMe's page links x.com/realtryhackme; GitHub's links x.com/github).
    Those say nothing about the person, so a handle containing the brand of the
    page it was found on, or of the site it points to, is dropped.
    """
    h = _norm_handle(handle)
    for host in hosts:
        brand = _norm_handle(_brand(host or ""))
        if len(brand) >= 4 and brand in h:
            return True
    return False


def extract_links(page: str, page_url: str, username: str = "") -> tuple[list[str], list[str]]:
    """Outbound links a profile page points to (other profiles, a personal site) and its mailto addresses.

    Only links off the site itself count: a profile's own navigation says
    nothing about the person. Profiles on other known sites are kept first.
    """
    from app.search.profiles import handle_relates_to, is_known_site, match_profile

    page_host = urlparse(page_url).hostname or ""
    own = _base_domain(page_host)
    profiles, sites, seen = [], [], set()
    # Site-wide navigation and footers carry the site's own links, not the person's.
    for href in _HREF.findall(_CHROME.sub(" ", page)):
        href = html.unescape(href).strip()
        if not href.startswith(("http://", "https://")):
            continue
        host = (urlparse(href).hostname or "").lower()
        if not host or _base_domain(host) == own or _BOILERPLATE.search(host):
            continue
        profile = match_profile(href)
        if profile is None and is_known_site(href):
            continue  # share buttons, hashtag and search pages on social sites
        # The site's own accounts, unless the handle is the person's own
        # (janedoe.com linking x.com/janedoe is exactly the link we want).
        if (profile is not None and is_site_account(profile.handle, page_host, host)
                and not (username and handle_relates_to(profile.handle, username))):  # fmt: skip
            continue
        key = profile.url if profile else href.rstrip("/")
        if key in seen:
            continue
        seen.add(key)
        (profiles if profile else sites).append(key)
    emails = sorted({m.lower() for m in _MAILTO.findall(page)})[:5]
    return (profiles + sites)[:MAX_LINKS], emails


def classify(url: str, username: str, status_code: int, final_url: str, page: str) -> Verdict:
    """Decide what a fetched profile page proves. Pure, so it is easy to test."""
    head = page[:60_000]
    preview = extract_preview(head)
    title_text = " ".join(preview.get(k, "") for k in ("title", "page_title"))
    if status_code in (404, 410):
        return Verdict(REJECTED, f"page not found (HTTP {status_code})", preview)
    if status_code in (401, 403, 429, 503) or _BOT_WALL.search(title_text):
        return Verdict(UNVERIFIED, f"blocked by bot protection (HTTP {status_code})", preview)
    if status_code >= 400:
        return Verdict(UNVERIFIED, f"site answered HTTP {status_code}", preview)

    user = _fold(username)
    requested, final = urlparse(url), urlparse(final_url)
    # Only the path counts: login redirects carry the profile in ?next=.
    if final_url != url and user not in _fold(final.path):
        if _LOGIN_PATH.search(final.path):
            return Verdict(REJECTED, "redirects to a login page", preview)
        if final.path in ("", "/") or (final.hostname or "") != (requested.hostname or ""):
            return Verdict(REJECTED, "redirects away from the profile", preview)

    if _NOT_FOUND.search(title_text):
        return Verdict(REJECTED, "the page says the profile does not exist", preview)

    fields = ("title", "page_title", "description", "username", "canonical")
    matched = [k for k in fields if user and user in _fold(preview.get(k, ""))]
    if matched:
        links, emails = extract_links(page, final_url, username)
        if links:
            preview["links"] = links
        if emails:
            preview["emails"] = emails
        preview["matched_in"] = matched
        if text := excerpt(_visible_text(head), [username]):
            preview["excerpt"] = text
        where = "title" if {"title", "page_title"} & set(matched) else matched[0].replace("_", " ")
        return Verdict(VERIFIED, f"profile page names the username in its {where}", preview)
    if _LOGIN.search(title_text):
        return Verdict(UNVERIFIED, "login wall: the profile is only visible when signed in", preview)
    visible = _TAGS.sub(" ", head)
    # Body text last: real profiles often load captcha scripts for their own forms.
    if _BOT_WALL.search(visible[:3000]):
        return Verdict(UNVERIFIED, "blocked by bot protection", preview)
    if _NOT_FOUND.search(visible[:4000]):
        return Verdict(REJECTED, "the page says the profile does not exist", preview)
    if user and user in _fold(visible):
        if text := excerpt(_visible_text(head), [username]):
            preview["excerpt"] = text
        preview["matched_in"] = ["body"]
        return Verdict(UNVERIFIED, "username appears on the page but not as its subject", preview)
    return Verdict(UNVERIFIED, "the page does not mention the username", preview)


def _retry_delay(resp: httpx.Response | None) -> float:
    if resp is not None:
        try:
            return min(_MAX_RETRY_AFTER, max(0.0, float(resp.headers.get("retry-after", ""))))
        except ValueError:
            pass
    return 0.5 + random.random()  # noqa: S311 — jitter, not security


async def _fetch_once(client: httpx.AsyncClient, url: str, username: str) -> tuple[Verdict, httpx.Response | None]:
    async with client.stream("GET", url) as resp:
        chunks, size = [], 0
        async for chunk in resp.aiter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= MAX_BYTES:
                break
        body = b"".join(chunks)[:MAX_BYTES].decode(resp.encoding or "utf-8", "replace")
        verdict = classify(url, username, resp.status_code, str(resp.url), body)
        verdict.preview["status"] = resp.status_code
        return verdict, resp


async def fetch_and_classify(client: httpx.AsyncClient, url: str, username: str) -> Verdict:
    """Fetch and classify a profile page, with one retry for a timeout, 429 or a 5xx gateway error."""
    for attempt in (1, 2):
        try:
            verdict, resp = await _fetch_once(client, url, username)
        except httpx.TooManyRedirects:
            return Verdict(REJECTED, "redirect loop")
        except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
            if attempt == 1:
                await asyncio.sleep(_retry_delay(None))
                continue
            return Verdict(UNVERIFIED, f"could not load the page ({exc.__class__.__name__})")
        except httpx.HTTPError as exc:
            return Verdict(UNVERIFIED, f"could not load the page ({exc.__class__.__name__})")
        if attempt == 1 and resp is not None and resp.status_code in _RETRY_STATUS:
            await asyncio.sleep(_retry_delay(resp))
            continue
        return verdict
    return verdict


# One client (connection pool, keep-alive) and one set of per-host limits per
# event loop, shared by every job: the same hosts come up again and again.
_clients: dict[tuple, httpx.AsyncClient] = {}
_host_limits: dict[int, dict[str, asyncio.Semaphore]] = {}


def _client() -> httpx.AsyncClient:
    from app.proxy import proxy_for

    settings = get_settings()
    proxy = proxy_for("verify") if transport is None else None
    key = (id(asyncio.get_running_loop()), proxy, transport, settings.verify_timeout_seconds)
    client = _clients.get(key)
    if client is None or client.is_closed:
        client = _clients[key] = httpx.AsyncClient(
            transport=transport,
            proxy=proxy,
            headers=BROWSER_HEADERS,
            timeout=settings.verify_timeout_seconds,
            follow_redirects=True,
            max_redirects=5,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10, keepalive_expiry=30),
        )
    return client


def _host_limit(host: str) -> asyncio.Semaphore:
    limits = _host_limits.setdefault(id(asyncio.get_running_loop()), {})
    if len(limits) > 2048:
        limits.clear()
    return limits.setdefault(host, asyncio.Semaphore(PER_HOST))


async def close_clients() -> None:
    """Close the pooled connections of the running loop (idle, shutdown, end of a worker job)."""
    loop_id = id(asyncio.get_running_loop())
    for key in [k for k in _clients if k[0] == loop_id]:
        await _clients.pop(key).aclose()
    _host_limits.pop(loop_id, None)


@dataclass
class VerificationStats:
    counts: Counter = field(default_factory=Counter)
    reasons: Counter = field(default_factory=Counter)
    # How each page check was answered: fetched now, from this scan's cache, or from the case.
    sources: Counter = field(default_factory=Counter)

    def merge(self, other: VerificationStats) -> None:
        self.counts.update(other.counts)
        self.reasons.update(other.reasons)
        self.sources.update(other.sources)

    def as_dict(self) -> dict:
        return {"counts": dict(self.counts), "reasons": dict(self.reasons.most_common(5)),
                "sources": dict(self.sources)}  # fmt: skip


async def verify_candidates(
    candidates: list[EntityCandidate], known: dict[str, dict] | None = None
) -> tuple[list[EntityCandidate], VerificationStats]:
    """Check each account candidate's page; drop rejected ones, annotate the rest.

    ``known`` maps a URL to the stored attributes of an entity in the case that
    was verified recently: those pages are not fetched again. Pages checked
    moments ago (another tool, a pivot run) come from the verdict cache.
    """
    from app import pagecache

    settings = get_settings()
    stats = VerificationStats()
    known = known or {}
    accounts = [c for c in candidates if c.type == "account" and c.attributes.get("url")]
    if not settings.verify_accounts or not accounts:
        return candidates, stats

    todo = accounts[: settings.verify_max_per_job]
    overall = asyncio.Semaphore(settings.verify_concurrency)
    cache = pagecache.verdicts()
    client = _client()
    verdicts: dict[int, Verdict] = {}

    async def one(cand: EntityCandidate) -> None:
        url = cand.attributes["url"]
        stored = known.get(url)
        if stored is not None:
            reason = stored.get("verification_reason") or "profile page names the username"
            verdicts[id(cand)] = Verdict(VERIFIED, reason, dict(stored.get("preview") or {}))
            stats.sources["reused"] += 1
            return
        username = cand.attributes.get("username") or ""

        async def fetch() -> Verdict:
            async with overall, _host_limit(urlparse(url).hostname or ""):
                verdict = await fetch_and_classify(client, url, username)
            verdict.preview.setdefault("checked_at", datetime.now(UTC).isoformat(timespec="seconds"))
            return verdict

        # A failed load is not worth remembering: the next tool may get through.
        verdict, cached = await cache.get_or_fetch(
            (url, _fold(username)), fetch, cacheable=lambda v: not v.reason.startswith("could not load")
        )
        stats.sources["cached" if cached else "fetched"] += 1
        # Each candidate gets its own copy: attributes are edited per entity later.
        verdicts[id(cand)] = Verdict(verdict.status, verdict.reason, dict(verdict.preview))

    await asyncio.gather(*(one(c) for c in todo))

    kept = []
    for cand in candidates:
        if cand.type != "account" or not cand.attributes.get("url"):
            kept.append(cand)
            continue
        verdict = verdicts.get(id(cand)) or Verdict(UNVERIFIED, "not checked (verification limit reached)")
        stats.counts[verdict.status] += 1
        if verdict.status != VERIFIED:
            stats.reasons[verdict.reason] += 1
        if verdict.status == REJECTED:
            continue
        cand.attributes = {
            **cand.attributes,
            "verification": verdict.status,
            "verification_reason": verdict.reason,
        }
        if verdict.preview:
            cand.attributes["preview"] = verdict.preview
        kept.append(cand)
    return kept, stats


def linked_accounts(candidates: list[EntityCandidate]) -> list[EntityCandidate]:
    """Accounts that verified profile pages link to, as new candidates.

    People link their own accounts (a GitHub bio pointing at a personal site,
    an X profile linking a LinkedIn page). A link from a checked profile of the
    subject is much stronger evidence than a username coincidence, so these
    start with a higher prior; they are verified like any other account.
    """
    from app.search.profiles import handle_relates_to, match_profile

    known = {c.value for c in candidates}
    out: dict[str, EntityCandidate] = {}
    for cand in candidates:
        attrs = cand.attributes or {}
        if cand.type != "account" or attrs.get("verification") != VERIFIED:
            continue
        source = attrs.get("site") or urlparse(cand.value).hostname
        for link in (attrs.get("preview") or {}).get("links") or []:
            profile = match_profile(link)
            if profile is None or profile.url in known or profile.url in out:
                continue
            # Also applied here for previews stored before the filter existed.
            hosts = (urlparse(cand.value).hostname or "", urlparse(profile.url).hostname or "")
            own = handle_relates_to(profile.handle, attrs.get("username") or "")
            if is_site_account(profile.handle, *hosts) and not own:
                continue
            out[profile.url] = EntityCandidate(
                type="account",
                value=profile.url,
                attributes={
                    "site": profile.site,
                    "username": profile.handle,
                    "url": profile.url,
                    "host": urlparse(profile.url).hostname,
                    "origin": f"linked from the {source} profile",
                    "linked_from": cand.value,
                },
                source_reliability="C",
                confidence=0.6,
                field_confidence={"exists": 0.7, "same_person": 0.6},
                relation_type="has_account",
                relation_explanation=f"the {source} profile links to it",
            )
    return list(out.values())
