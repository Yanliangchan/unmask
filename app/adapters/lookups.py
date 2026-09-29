"""Direct lookups against public APIs that need no key (or work better with one).

Unlike username checkers, these ask the site itself: GitHub's API either has
the user or it doesn't, so an account found here needs no page check, and it
comes with the person's own fields (name, location, bio, linked accounts)
that the correlation engine uses to tell namesakes apart.

Every lookup runs one or two HTTP requests; a missing user is an empty
result, anything else unexpected is an error, never "nothing found".
"""

from __future__ import annotations

import hashlib
import html
import re
from datetime import UTC, datetime
from urllib.parse import quote, urlparse

import httpx

from app.adapters import http
from app.adapters.base import (
    AdapterError,
    EntityCandidate,
    HealthResult,
    InvalidTarget,
    RawResult,
    SignatureMismatch,
    ToolAdapter,
    validate_domain,
    validate_email,
)
from app.config import get_settings

_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")
_LINK = re.compile(r"https?://[^\s\"'<>)]+", re.I)
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def validate_handle(value: str) -> str:
    value = value.strip().lstrip("@")
    if not _USERNAME.match(value):
        raise InvalidTarget("usernames may only contain letters, digits, '.', '_' and '-'")
    return value


async def fetch_json(
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float = 30,  # noqa: ASYNC109 — passed through to httpx
    missing: tuple[int, ...] = (404,),
) -> object | None:
    """GET JSON. ``missing`` statuses mean "no such record" and return None; other failures raise."""
    try:
        async with http.client(timeout) as c:
            resp = await c.get(url, params=params, headers=headers)
    except httpx.HTTPError as exc:
        raise AdapterError(f"request failed: {exc.__class__.__name__}") from exc
    host = resp.url.host
    if resp.status_code in missing:
        return None
    if resp.status_code in (401, 403):
        raise AdapterError(f"HTTP {resp.status_code} from {host}: the API key was rejected or lacks access")
    if resp.status_code == 429:
        raise AdapterError(f"HTTP 429 from {host}: rate-limited, try again later")
    if resp.status_code != 200:
        raise AdapterError(f"HTTP {resp.status_code} from {host}")
    try:
        return resp.json()
    except ValueError as exc:
        raise SignatureMismatch(f"{host} returned a body that isn't JSON") from exc


def api_account(
    site: str,
    url: str,
    handle: str,
    *,
    profile: dict | None = None,
    links: list[str] | None = None,
    emails: list[str] | None = None,
    title: str = "",
    reliability: str = "B",
    confidence: float = 0.55,
    relation: str = "has_account",
    explanation: str = "",
    verification: str | None = "verified",
    reason: str | None = None,
) -> EntityCandidate:
    """An account the site's own API confirmed, with the person's fields for correlation."""
    profile = {k: v for k, v in (profile or {}).items() if v not in (None, "", [], {})}
    preview = {k: v for k, v in {"title": title, "links": links or [], "emails": emails or []}.items() if v}
    return EntityCandidate(
        type="account",
        value=url,
        attributes={
            "site": site,
            "url": url,
            "username": handle,
            "host": urlparse(url).hostname,
            **(
                {"verification": verification, "verification_reason": reason or f"{site}'s API returned this profile"}
                if verification
                else {}
            ),
            **({"profile": profile} if profile else {}),
            **({"preview": preview} if preview else {}),
        },
        source_reliability=reliability,
        confidence=confidence,
        field_confidence={"exists": 0.95 if verification == "verified" else 0.7, "same_person": confidence},
        relation_type=relation,
        relation_explanation=explanation or f"{site} account '{handle}'",
    )


def linked(site: str, url: str, handle: str, source: str, *, proven: bool = False) -> EntityCandidate:
    """An account a profile itself links to (the owner put it there)."""
    return api_account(
        site,
        url,
        handle,
        reliability="B" if proven else "C",
        confidence=0.75 if proven else 0.6,
        explanation=f"the {source} profile {'proves ownership of' if proven else 'links to'} it",
        verification="verified" if proven else None,
        reason=f"ownership proven by a signed {source} proof" if proven else None,
    )


def enrich(kind: str, value: str, tool: str, details: dict) -> EntityCandidate:
    """Details about a finding that already exists (the target itself, usually).

    Nested under the tool's name so they never overwrite the finding's own
    attributes, and with no score of their own so they can't raise its confidence.
    """
    details = {k: v for k, v in details.items() if v not in (None, "", [], {})}
    return EntityCandidate(kind, value, {tool: details}, "F", 0.0, {})


def profile_links(*texts: str) -> tuple[list[str], list[str]]:
    """Links and email addresses written in a bio or 'about' text."""
    joined = " ".join(html.unescape(t or "") for t in texts)
    links = list(dict.fromkeys(u.rstrip(".,;") for u in _LINK.findall(joined)))[:10]
    emails = sorted({e.lower() for e in _EMAIL.findall(joined)})[:5]
    return links, emails


def _as_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    return value if value.startswith(("http://", "https://")) else f"https://{value}"


# --- GitHub --------------------------------------------------------------------------------------


class GitHubAdapter(ToolAdapter):
    name = "github"
    label = "GitHub"
    input_types = ["username", "email"]
    description = (
        "GitHub's API: the profile behind a username (name, location, company, linked accounts), and for an "
        "email address, the accounts that made public commits with it."
    )
    health_check_target = "torvalds"
    timeout_seconds = 60
    api = "https://api.github.com"

    def _headers(self) -> dict:
        h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        if token := get_settings().github_token:
            h["Authorization"] = f"Bearer {token}"
        return h

    async def _user(self, login: str) -> dict | None:
        user = await fetch_json(f"{self.api}/users/{quote(login)}", headers=self._headers())
        if user is None:
            return None
        if not isinstance(user, dict) or "login" not in user:
            raise SignatureMismatch("GitHub returned an unexpected user record")
        socials = await fetch_json(f"{self.api}/users/{quote(login)}/social_accounts", headers=self._headers())
        user["_social"] = socials if isinstance(socials, list) else []
        return user

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        if "@" in target_value:
            email = validate_email(target_value)
            data = await fetch_json(
                f"{self.api}/search/commits",
                params={"q": f"author-email:{email}", "per_page": 30},
                headers=self._headers(),
                missing=(404, 422),
            )
            logins = []
            for item in (data or {}).get("items", []) if isinstance(data, dict) else []:
                login = ((item.get("author") or {}).get("login") or "").strip()
                if login and login not in logins:
                    logins.append(login)
            users = [u for u in [await self._user(login) for login in logins[:3]] if u]
            return [RawResult(self.name, email, {"email": email, "users": users})]
        login = validate_handle(target_value)
        user = await self._user(login)
        return [RawResult(self.name, login, {"users": [user] if user else []})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        out: list[EntityCandidate] = []
        email = raw.payload.get("email")
        for u in raw.payload["users"]:
            login, url = u["login"], u.get("html_url") or f"https://github.com/{u['login']}"
            blog = _as_url(u.get("blog") or "")
            bio_links, bio_emails = profile_links(u.get("bio") or "")
            links = [x for x in [blog, *[s.get("url", "") for s in u.get("_social") or []], *bio_links] if x]
            if u.get("twitter_username"):
                links.append(f"https://x.com/{u['twitter_username']}")
            links = list(dict.fromkeys(links))
            emails = sorted({*(bio_emails), *([u["email"].lower()] if u.get("email") else [])})
            profile = {
                "name": u.get("name"),
                "location": u.get("location"),
                "company": u.get("company"),
                "bio": u.get("bio"),
                "created": u.get("created_at"),
                "followers": u.get("followers"),
                "public_repos": u.get("public_repos"),
            }
            out.append(
                api_account(
                    "GitHub",
                    url,
                    login,
                    profile=profile,
                    links=links,
                    emails=emails,
                    title=f"{u.get('name') or login} ({login}) · GitHub",
                    confidence=0.8 if email else 0.55,
                    relation="committed_as" if email else "has_account",
                    explanation=(
                        f"public commits authored with this address belong to '{login}'"
                        if email
                        else f"GitHub account '{login}'"
                    ),
                )
            )
            if u.get("twitter_username"):
                h = u["twitter_username"]
                out.append(linked("X", f"https://x.com/{h}", h, "GitHub"))
            for s in u.get("_social") or []:
                if s.get("provider") == "twitter":
                    continue
                if s.get("url"):
                    handle = s["url"].rstrip("/").rsplit("/", 1)[-1]
                    out.append(linked(str(s.get("provider") or "profile").capitalize(), s["url"], handle, "GitHub"))
            for e in emails:
                out.append(
                    EntityCandidate(
                        "email",
                        e,
                        {"origin": "GitHub profile", "url": url},
                        "B",
                        0.7,
                        {"same_person": 0.7},
                        "has_email",
                        f"listed on the GitHub profile '{login}'",
                    )
                )
        return out

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        if any((c.attributes.get("profile") or {}).get("name") == "Linus Torvalds" for c in candidates):
            limit = "with a token" if get_settings().github_token else "without a token (60 lookups an hour)"
            return HealthResult(True, f"known profile found, {limit}")
        return HealthResult(False, "the known profile wasn't returned")


# --- GitLab --------------------------------------------------------------------------------------


class GitLabAdapter(ToolAdapter):
    name = "gitlab"
    label = "GitLab"
    input_types = ["username"]
    description = "GitLab's API: the profile behind a username, with its name, bio, location and linked accounts."
    health_check_target = "sytses"
    timeout_seconds = 60
    api = "https://gitlab.com/api/v4"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value)
        found = await fetch_json(f"{self.api}/users", params={"username": login})
        if not isinstance(found, list):
            raise SignatureMismatch("GitLab returned an unexpected user list")
        users = []
        for u in found[:1]:
            detail = await fetch_json(f"{self.api}/users/{int(u['id'])}")
            users.append(detail if isinstance(detail, dict) else u)
        return [RawResult(self.name, login, {"users": users})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        out = []
        for u in raw.payload["users"]:
            login = u.get("username") or raw.target_value
            url = u.get("web_url") or f"https://gitlab.com/{login}"
            bio_links, bio_emails = profile_links(u.get("bio") or "")
            links = [_as_url(u.get("website_url") or "")] + bio_links
            if u.get("twitter"):
                links.append(f"https://x.com/{u['twitter'].lstrip('@')}")
            if u.get("linkedin"):
                links.append(
                    _as_url(u["linkedin"]) if "/" in u["linkedin"] else f"https://www.linkedin.com/in/{u['linkedin']}"
                )
            if u.get("github"):
                links.append(f"https://github.com/{u['github']}")
            links = list(dict.fromkeys(x for x in links if x))
            emails = sorted({*bio_emails, *([u["public_email"].lower()] if u.get("public_email") else [])})
            out.append(
                api_account(
                    "GitLab",
                    url,
                    login,
                    links=links,
                    emails=emails,
                    title=f"{u.get('name') or login} · GitLab",
                    profile={
                        "name": u.get("name"),
                        "location": u.get("location"),
                        "bio": u.get("bio"),
                        "company": u.get("organization"),
                        "job_title": u.get("job_title"),
                        "created": u.get("created_at"),
                    },
                )
            )
            if u.get("twitter"):
                h = u["twitter"].lstrip("@")
                out.append(linked("X", f"https://x.com/{h}", h, "GitLab"))
            if u.get("github"):
                out.append(linked("GitHub", f"https://github.com/{u['github']}", u["github"], "GitLab"))
            for e in emails:
                out.append(
                    EntityCandidate(
                        "email",
                        e,
                        {"origin": "GitLab profile", "url": url},
                        "B",
                        0.7,
                        {"same_person": 0.7},
                        "has_email",
                        f"public email on GitLab '{login}'",
                    )
                )
        return out


# --- Keybase -------------------------------------------------------------------------------------

_KEYBASE_SITES = {
    "twitter": ("X", "https://x.com/{}"),
    "github": ("GitHub", "https://github.com/{}"),
    "reddit": ("Reddit", "https://www.reddit.com/user/{}"),
    "hackernews": ("Hacker News", "https://news.ycombinator.com/user?id={}"),
    "facebook": ("Facebook", "https://www.facebook.com/{}"),
    "mastodon.social": ("Mastodon", "https://mastodon.social/@{}"),
}


class KeybaseAdapter(ToolAdapter):
    name = "keybase"
    label = "Keybase"
    input_types = ["username"]
    description = "Keybase: accounts on other sites that a Keybase user has cryptographically proven they own."
    health_check_target = "chris"
    timeout_seconds = 60

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value)
        data = await fetch_json(
            "https://keybase.io/_/api/1.0/user/lookup.json",
            params={"usernames": login, "fields": "basics,profile,proofs_summary"},
        )
        if not isinstance(data, dict) or "status" not in data:
            raise SignatureMismatch("Keybase returned an unexpected response")
        them = [t for t in (data.get("them") or []) if t]
        return [RawResult(self.name, login, {"them": them})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        out = []
        for t in raw.payload["them"]:
            login = (t.get("basics") or {}).get("username") or raw.target_value
            prof = t.get("profile") or {}
            proofs = ((t.get("proofs_summary") or {}).get("all")) or []
            links = [p.get("service_url") for p in proofs if p.get("service_url")]
            out.append(
                api_account(
                    "Keybase",
                    f"https://keybase.io/{login}",
                    login,
                    links=links,
                    title=f"{prof.get('full_name') or login} · Keybase",
                    profile={"name": prof.get("full_name"), "location": prof.get("location"), "bio": prof.get("bio")},
                )
            )
            for p in proofs:
                kind, handle = str(p.get("proof_type") or ""), str(p.get("nametag") or "")
                if kind in ("dns", "generic_web_site"):
                    if handle:
                        out.append(
                            EntityCandidate(
                                "domain",
                                handle.lower(),
                                {"origin": "Keybase proof", "proof_url": p.get("proof_url")},
                                "B",
                                0.75,
                                {"same_person": 0.75},
                                "controls_domain",
                                f"Keybase user '{login}' proved control of it",
                            )
                        )
                    continue
                site, pattern = _KEYBASE_SITES.get(kind, (kind.capitalize(), ""))
                url = p.get("service_url") or (pattern.format(handle) if pattern else "")
                if handle and url:
                    out.append(linked(site, url, handle, "Keybase", proven=True))
        return out


# --- Hacker News ---------------------------------------------------------------------------------


class HackerNewsAdapter(ToolAdapter):
    name = "hackernews"
    label = "Hacker News"
    input_types = ["username"]
    description = "Hacker News profiles: account age, karma, and the links people put in their 'about' text."
    health_check_target = "pg"
    timeout_seconds = 30

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value)
        user = await fetch_json(f"https://hacker-news.firebaseio.com/v0/user/{quote(login)}.json")
        return [RawResult(self.name, login, {"user": user if isinstance(user, dict) else None})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        u = raw.payload["user"]
        if not u:
            return []
        raw_about = html.unescape(u.get("about") or "")
        about = re.sub(r"<[^>]+>", " ", raw_about)
        links, emails = profile_links(raw_about)  # before stripping tags: links live in href attributes
        created = datetime.fromtimestamp(u["created"], UTC).date().isoformat() if u.get("created") else None
        login = u.get("id") or raw.target_value
        out = [
            api_account(
                "Hacker News",
                f"https://news.ycombinator.com/user?id={login}",
                login,
                links=links,
                emails=emails,
                title=f"Profile: {login} | Hacker News",
                profile={"bio": about.strip()[:500], "created": created, "karma": u.get("karma")},
            )
        ]
        for e in emails:
            out.append(
                EntityCandidate(
                    "email",
                    e,
                    {"origin": "Hacker News about text"},
                    "C",
                    0.65,
                    {"same_person": 0.65},
                    "has_email",
                    f"written in the Hacker News profile '{login}'",
                )
            )
        return out


# --- Gravatar ------------------------------------------------------------------------------------


class GravatarAdapter(ToolAdapter):
    name = "gravatar"
    label = "Gravatar"
    input_types = ["email"]
    description = "Gravatar: the public profile tied to an email address (name, location, linked accounts, photo)."
    health_check_target = "beau@dentedreality.com.au"
    timeout_seconds = 30

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        email = validate_email(target_value).lower()
        # The profile endpoint is keyed by the MD5 of the address (an identifier, not a security use).
        digest = hashlib.md5(email.encode(), usedforsecurity=False).hexdigest()
        data = await fetch_json(f"https://en.gravatar.com/{digest}.json")
        entry = (data or {}).get("entry", [None])[0] if isinstance(data, dict) else None
        return [RawResult(self.name, email, {"email": email, "hash": digest, "entry": entry})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        e = raw.payload["entry"]
        if not e:
            return []
        login = e.get("preferredUsername") or e.get("displayName") or raw.payload["hash"][:12]
        url = e.get("profileUrl") or f"https://gravatar.com/{login}"
        accounts = e.get("accounts") or []
        links = [a.get("url") for a in accounts if a.get("url")] + [
            u.get("value") for u in e.get("urls") or [] if u.get("value")
        ]
        name = (e.get("name") or {}).get("formatted") or e.get("displayName")
        out = [
            api_account(
                "Gravatar",
                url,
                login,
                links=links,
                title=f"{name or login} · Gravatar",
                confidence=0.85,
                relation="has_profile",
                explanation="Gravatar profile registered to this exact address",
                profile={
                    "name": name,
                    "location": e.get("currentLocation"),
                    "bio": e.get("aboutMe"),
                    "photo": (e.get("photos") or [{}])[0].get("value"),
                },
            )
        ]
        for a in accounts:
            if a.get("url") and a.get("username"):
                out.append(
                    linked(a.get("name") or a.get("shortname") or "profile", a["url"], a["username"], "Gravatar")
                )
        if login and login != raw.payload["hash"][:12]:
            out.append(
                EntityCandidate(
                    "username",
                    login,
                    {"origin": "Gravatar username"},
                    "B",
                    0.75,
                    {"same_person": 0.75},
                    "uses_handle",
                    "the address's Gravatar username",
                )
            )
        return out

    async def health_check(self) -> HealthResult:
        try:
            raws = await self.run(self.health_check_target, [])
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        return HealthResult(
            True, "Gravatar API answered" + (" with the known profile" if raws[0].payload["entry"] else "")
        )


# --- LeakCheck (public API) ----------------------------------------------------------------------


class LeakCheckAdapter(ToolAdapter):
    name = "leakcheck"
    label = "LeakCheck"
    input_types = ["email", "username"]
    description = (
        "LeakCheck's free public API: which breach sources list an email address or username (names and dates only)."
    )
    health_check_target = "test@example.com"
    timeout_seconds = 30

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        value = validate_email(target_value) if "@" in target_value else validate_handle(target_value)
        data = await fetch_json("https://leakcheck.io/api/public", params={"check": value})
        if not isinstance(data, dict) or "success" not in data:
            raise SignatureMismatch("LeakCheck returned an unexpected response")
        if not data.get("success") and "not found" not in str(data.get("error", "")).lower():
            raise AdapterError(f"LeakCheck: {str(data.get('error') or 'lookup failed')[:200]}")
        return [RawResult(self.name, value, data)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        data = raw.payload
        if not data.get("success"):
            return []
        fields = data.get("fields") or []
        return [
            EntityCandidate(
                type="breach",
                value=f"{s.get('name') or 'Unknown source'} (LeakCheck)",
                attributes={
                    "breach": s.get("name"),
                    "date": s.get("date"),
                    "source": "leakcheck",
                    "fields": fields,
                    "identifier": raw.target_value,
                },
                source_reliability="C",
                confidence=0.6 if "@" in raw.target_value else 0.4,
                field_confidence={"in_breach": 0.7, "same_person": 0.6 if "@" in raw.target_value else 0.4},
                relation_type="exposed_in",
                relation_explanation=f"listed in {s.get('name') or 'a breach'} according to LeakCheck",
            )
            for s in data.get("sources") or []
        ]

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        return HealthResult(True, "LeakCheck public API answered")


# --- Wayback Machine -----------------------------------------------------------------------------

_PEOPLE_PAGES = re.compile(
    r"/(about|team|people|staff|contact|leadership|who-we-are|company|founders?)(?:[/_.-]|$)", re.I
)


class WaybackAdapter(ToolAdapter):
    name = "wayback"
    label = "Wayback Machine"
    input_types = ["domain"]
    description = "Internet Archive captures of a domain's about, team and contact pages, including ones since removed."
    health_check_target = "example.com"
    timeout_seconds = 90

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        rows = await fetch_json(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "timestamp,original,statuscode",
                "filter": "statuscode:200",
                "collapse": "urlkey",
                "limit": 5000,
            },
            timeout=self.timeout_seconds,
        )
        if rows is not None and not isinstance(rows, list):
            raise SignatureMismatch("the Wayback Machine returned an unexpected capture list")
        return [RawResult(self.name, domain, {"domain": domain, "rows": (rows or [])[1:]})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        rows = raw.payload["rows"]
        pages: dict[str, tuple[str, str]] = {}
        for ts, original, *_ in rows:
            path = urlparse(original).path
            if _PEOPLE_PAGES.search(path) and len(pages) < 30:
                key = path.rstrip("/").lower()
                if key not in pages or ts > pages[key][0]:
                    pages[key] = (ts, original)
        out = []
        for ts, original in pages.values():
            archive = f"https://web.archive.org/web/{ts}/{original}"
            when = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}"
            out.append(
                EntityCandidate(
                    "web_mention",
                    archive,
                    {
                        "url": archive,
                        "title": f"Archived {urlparse(original).path} ({when})",
                        "snippet": f"Internet Archive capture of {original} from {when}",
                        "captured": when,
                        "original": original,
                    },
                    "B",
                    0.35,
                    {"relevant": 0.4},
                    "archived_page",
                    f"archived page of {raw.payload['domain']} ({when})",
                )
            )
        return out

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        return HealthResult(True, "the Wayback Machine answered")


# --- RDAP (domain registration) ------------------------------------------------------------------


def _vcard(entity: dict) -> dict:
    out = {}
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4:
            out.setdefault(item[0], item[3])
    return out


class RdapAdapter(ToolAdapter):
    name = "rdap"
    label = "Domain registration (RDAP)"
    input_types = ["domain"]
    description = (
        "The official registration record for a domain: registrar, dates, name servers, and the registrant "
        "where it's public."
    )
    health_check_target = "example.com"
    timeout_seconds = 30

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        data = await fetch_json(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"})
        return [RawResult(self.name, domain, {"domain": domain, "rdap": data or {}})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        rdap, domain = raw.payload["rdap"], raw.payload["domain"]
        if not rdap:
            return []
        events = {e.get("eventAction"): (e.get("eventDate") or "")[:10] for e in rdap.get("events") or []}
        people = {}
        for ent in rdap.get("entities") or []:
            card = _vcard(ent)
            for role in ent.get("roles") or []:
                people[role] = card
        registrar = (people.get("registrar") or {}).get("fn")
        registrant = people.get("registrant") or {}
        attrs = {
            "registrar": registrar,
            "registered": events.get("registration"),
            "expires": events.get("expiration"),
            "updated": events.get("last changed"),
            "nameservers": [n.get("ldhName", "").lower() for n in rdap.get("nameservers") or []],
            "registrant_org": registrant.get("org"),
            "registrant_name": registrant.get("fn"),
            "registrant_country": (registrant.get("adr") or [None] * 7)[-1]
            if isinstance(registrant.get("adr"), list)
            else None,
            "origin": "RDAP registration record",
        }
        attrs.pop("origin", None)
        out = [enrich("domain", domain, "rdap", attrs)]
        redacted = re.compile(r"redacted|privacy|withheld|proxy|not disclosed", re.I)
        name = registrant.get("fn")
        if name and not redacted.search(str(name)):
            out.append(
                EntityCandidate(
                    "name",
                    str(name),
                    {"origin": "domain registrant (RDAP)"},
                    "B",
                    0.6,
                    {"same_person": 0.6},
                    "registered_by",
                    f"registrant of {domain}",
                )
            )
        email = registrant.get("email")
        if email and not redacted.search(str(email)):
            out.append(
                EntityCandidate(
                    "email",
                    str(email).lower(),
                    {"origin": "domain registrant (RDAP)"},
                    "B",
                    0.65,
                    {"same_person": 0.65},
                    "registered_by",
                    f"registrant contact for {domain}",
                )
            )
        return out

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        if candidates and candidates[0].attributes.get("rdap", {}).get("registered"):
            return HealthResult(True, "registration record returned for a known domain")
        return HealthResult(False, "no registration record for a known domain")
