"""Direct lookups on platforms with public profile APIs: the site itself says whether the user exists.

Like the GitHub and GitLab lookups (app/adapters/lookups.py), each of these asks the
platform directly instead of guessing from a page, so an account found here is
verified, and it comes with the person's own fields: display name, bio, location,
join date, links. Those are what the correlation engine uses to tell namesakes
apart. Links a platform itself has verified (Mastodon's rel="me" checks) count as
proven ownership.

A missing user is an empty result; anything unexpected is an error, never "nothing found".
"""

from __future__ import annotations

import html
import re
from datetime import UTC, datetime
from urllib.parse import quote

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
from app.adapters.lookups import _as_url, api_account, fetch_json, linked, profile_links, validate_handle


def _iso(value) -> str | None:
    """A date from epoch seconds, epoch milliseconds or an ISO string."""
    if value in (None, ""):
        return None
    if isinstance(value, int | float):
        secs = value / 1000 if value > 10**11 else value
        return datetime.fromtimestamp(secs, UTC).date().isoformat()
    return str(value)[:10]


def _text(value) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html.unescape(str(value or "")))).strip()


async def fetch_page(url: str, *, timeout: float = 30) -> tuple[int, str]:  # noqa: ASYNC109
    """GET an HTML page: (status, body). Transport failures raise."""
    try:
        async with http.client(timeout) as c:
            resp = await c.get(url, headers={"Accept": "text/html"})
    except httpx.HTTPError as exc:
        raise AdapterError(f"request failed: {exc.__class__.__name__}") from exc
    return resp.status_code, resp.text[:400_000]


def _email(e: str, origin: str, url: str, who: str) -> EntityCandidate:
    return EntityCandidate(
        "email",
        e.lower(),
        {"origin": origin, "url": url},
        "B",
        0.7,
        {"same_person": 0.7},
        "has_email",
        f"public email on {who}",
    )


class _Platform(ToolAdapter):
    input_types = ["username"]
    timeout_seconds = 45
    site = ""

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        if any(c.type == "account" for c in candidates):
            return HealthResult(True, f"known {self.site} profile found")
        return HealthResult(False, f"the known {self.site} profile wasn't returned")


# --- Reddit ---------------------------------------------------------------------------------------


class RedditAdapter(_Platform):
    name = "reddit"
    label = "Reddit"
    site = "Reddit"
    description = "Reddit's own profile data: account age, karma and the profile's description."
    health_check_target = "spez"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value)
        data = await fetch_json(
            f"https://www.reddit.com/user/{quote(login)}/about.json", headers={"Accept": "application/json"}
        )
        if data is not None and (not isinstance(data, dict) or data.get("kind") != "t2"):
            raise SignatureMismatch("Reddit returned something other than a user record")
        user = (data or {}).get("data") or None
        if user and user.get("is_suspended"):
            user = {**user, "_suspended": True}
        return [RawResult(self.name, login, {"user": user})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        u = raw.payload["user"]
        if not u:
            return []
        login = u.get("name") or raw.target_value
        sub = u.get("subreddit") or {}
        bio = _text(sub.get("public_description"))
        links, emails = profile_links(bio)
        url = f"https://www.reddit.com/user/{login}"
        return [
            api_account(
                "Reddit",
                url,
                login,
                links=links,
                emails=emails,
                title=f"{sub.get('title') or login} (u/{login}) · Reddit",
                profile={
                    "name": sub.get("title") if sub.get("title") != login else None,
                    "bio": bio,
                    "created": _iso(u.get("created_utc")),
                    "karma": (u.get("link_karma") or 0) + (u.get("comment_karma") or 0),
                    "suspended": True if u.get("_suspended") else None,
                },
            )
        ] + [_email(e, "Reddit profile", url, f"Reddit u/{login}") for e in emails]


# --- Bluesky --------------------------------------------------------------------------------------


class BlueskyAdapter(_Platform):
    name = "bluesky"
    label = "Bluesky"
    site = "Bluesky"
    description = (
        "Bluesky's public API: the profile for a handle (name, bio, join date). "
        "A custom-domain handle proves control of that domain."
    )
    health_check_target = "jay.bsky.team"
    api = "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        handle = validate_handle(target_value).lower()
        handles = [handle] if "." in handle else [f"{handle}.bsky.social"]
        for h in handles:
            # 400 is how the API says "no such profile".
            data = await fetch_json(self.api, params={"actor": h}, missing=(400, 404))
            if data is not None:
                if not isinstance(data, dict) or "did" not in data:
                    raise SignatureMismatch("Bluesky returned an unexpected profile record")
                return [RawResult(self.name, handle, {"profile": data})]
        return [RawResult(self.name, handle, {"profile": None})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        p = raw.payload["profile"]
        if not p:
            return []
        handle = p.get("handle") or raw.target_value
        bio = _text(p.get("description"))
        links, emails = profile_links(bio)
        url = f"https://bsky.app/profile/{handle}"
        out = [
            api_account(
                "Bluesky",
                url,
                handle,
                links=links,
                emails=emails,
                title=f"{p.get('displayName') or handle} (@{handle}) · Bluesky",
                profile={
                    "name": p.get("displayName"),
                    "bio": bio,
                    "created": _iso(p.get("createdAt")),
                    "followers": p.get("followersCount"),
                    "did": p.get("did"),
                },
            )
        ]
        if not handle.endswith(".bsky.social"):
            # A custom handle only resolves if its owner put the DID in that domain's DNS or well-known file.
            out.append(
                EntityCandidate(
                    "domain",
                    handle,
                    {"origin": "Bluesky handle", "url": url},
                    "B",
                    0.75,
                    {"same_person": 0.75},
                    "controls_domain",
                    f"the Bluesky handle '{handle}' is verified through this domain",
                )
            )
        return out + [_email(e, "Bluesky bio", url, f"Bluesky @{handle}") for e in emails]


# --- Mastodon -------------------------------------------------------------------------------------

MASTODON_INSTANCES = (
    "mastodon.social",
    "mastodon.online",
    "mstdn.social",
    "fosstodon.org",
    "hachyderm.io",
    "infosec.exchange",
    "mas.to",
    "mastodon.world",
)


class MastodonAdapter(_Platform):
    name = "mastodon"
    label = "Mastodon"
    site = "Mastodon"
    description = (
        "Looks the username up on the largest Mastodon servers. Profile links the server has verified "
        '(rel="me") count as proven ownership.'
    )
    health_check_target = "Gargron"
    timeout_seconds = 60

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        value = target_value.strip().lstrip("@")
        if "@" in value:  # user@instance
            user, _, inst = value.partition("@")
            pairs = [(validate_handle(user), inst.lower())]
        else:
            pairs = [(validate_handle(value), i) for i in MASTODON_INSTANCES]
        found, failures = [], 0
        for user, inst in pairs:
            if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", inst):
                continue
            try:
                acct = await fetch_json(f"https://{inst}/api/v1/accounts/lookup", params={"acct": user}, timeout=15)
            except AdapterError:
                failures += 1
                continue
            if isinstance(acct, dict) and acct.get("url"):
                found.append({**acct, "_instance": inst})
        if failures == len(pairs):
            raise AdapterError("no Mastodon server answered")
        return [RawResult(self.name, value, {"accounts": found, "failed": failures, "asked": len(pairs)})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        out = []
        for a in raw.payload["accounts"]:
            handle = f"{a.get('username')}@{a['_instance']}"
            bio = _text(a.get("note"))
            fields = a.get("fields") or []
            verified = [_text(f.get("value")) for f in fields if f.get("verified_at")]
            unverified = [_text(f.get("value")) for f in fields if not f.get("verified_at")]
            links, emails = profile_links(bio, *unverified)
            out.append(
                api_account(
                    "Mastodon",
                    a["url"],
                    handle,
                    links=[_as_url(v) for v in verified] + links,
                    emails=emails,
                    title=f"{a.get('display_name') or a.get('username')} (@{handle}) · Mastodon",
                    profile={
                        "name": a.get("display_name"),
                        "bio": bio,
                        "created": _iso(a.get("created_at")),
                        "followers": a.get("followers_count"),
                    },
                )
            )
            for v in verified:
                url = _as_url(v.split()[0]) if v else ""
                if url.startswith("http"):
                    out.append(linked("Website", url, url, "Mastodon", proven=True))
            out += [_email(e, "Mastodon profile", a["url"], f"Mastodon @{handle}") for e in emails]
        return out


# --- Docker Hub -----------------------------------------------------------------------------------


class DockerHubAdapter(_Platform):
    name = "dockerhub"
    label = "Docker Hub"
    site = "Docker Hub"
    description = "Docker Hub's API: the account behind a username, with full name, company, location and join date."
    health_check_target = "jpetazzo"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value).lower()
        data = await fetch_json(f"https://hub.docker.com/v2/users/{quote(login)}")
        if data is not None and (not isinstance(data, dict) or "username" not in data):
            raise SignatureMismatch("Docker Hub returned an unexpected user record")
        return [RawResult(self.name, login, {"user": data})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        u = raw.payload["user"]
        if not u:
            return []
        login = u["username"]
        site = _as_url(u.get("profile_url") or "")
        return [
            api_account(
                "Docker Hub",
                f"https://hub.docker.com/u/{login}",
                login,
                links=[site] if site else [],
                title=f"{u.get('full_name') or login} · Docker Hub",
                profile={
                    "name": u.get("full_name"),
                    "company": u.get("company"),
                    "location": u.get("location"),
                    "created": _iso(u.get("date_joined")),
                    "kind": u.get("type"),
                },
            )
        ]


# --- npm ------------------------------------------------------------------------------------------


class NpmAdapter(_Platform):
    name = "npm"
    label = "npm"
    site = "npm"
    description = "Packages a username maintains on npm, and the email address the registry lists for them."
    health_check_target = "sindresorhus"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value).lower()
        data = await fetch_json(
            "https://registry.npmjs.org/-/v1/search", params={"text": f"maintainer:{login}", "size": 20}
        )
        if not isinstance(data, dict) or "objects" not in data:
            raise SignatureMismatch("npm returned an unexpected search result")
        pkgs, emails = [], set()
        for o in data["objects"]:
            p = o.get("package") or {}
            mine = [m for m in p.get("maintainers") or [] if (m.get("username") or "").lower() == login]
            if mine:
                pkgs.append(p.get("name"))
                emails |= {m["email"].lower() for m in mine if m.get("email")}
        return [RawResult(self.name, login, {"packages": pkgs, "emails": sorted(emails), "total": data.get("total")})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        p = raw.payload
        if not p["packages"]:
            return []
        login = raw.target_value
        url = f"https://www.npmjs.com/~{login}"
        out = [
            api_account(
                "npm",
                url,
                login,
                emails=p["emails"],
                title=f"{login} · npm",
                profile={"packages": ", ".join(p["packages"][:10]), "package_count": p["total"]},
            )
        ]
        return out + [_email(e, "npm maintainer record", url, f"npm ~{login}") for e in p["emails"]]


# --- PyPI -----------------------------------------------------------------------------------------


class PyPIAdapter(_Platform):
    name = "pypi"
    label = "PyPI"
    site = "PyPI"
    description = "The Python Package Index profile for a username: display name, join date and projects."
    health_check_target = "dstufft"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value)
        status, body = await fetch_page(f"https://pypi.org/user/{quote(login)}/")
        if status == 404:
            return [RawResult(self.name, login, {"user": None})]
        if "Client Challenge" in body[:2000]:
            raise SignatureMismatch("PyPI showed a bot check instead of the profile")
        if status != 200 or "author-profile" not in body:
            raise SignatureMismatch(f"PyPI answered HTTP {status} without a profile page")
        name = re.search(r'author-profile__name">\s*([^<]+)', body)
        joined = re.search(r"Joined\s*<time[^>]*datetime=\"([^\"]+)\"", body)
        projects = re.findall(r'class="package-snippet__title">\s*([^<]+)', body)
        return [
            RawResult(
                self.name,
                login,
                {
                    "user": {
                        "name": name.group(1).strip() if name else None,
                        "joined": joined.group(1) if joined else None,
                        "projects": [p.strip() for p in projects][:20],
                    }
                },
            )
        ]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        u = raw.payload["user"]
        if u is None:
            return []
        login = raw.target_value
        return [
            api_account(
                "PyPI",
                f"https://pypi.org/user/{login}/",
                login,
                title=f"Profile of {login} · PyPI",
                profile={
                    "name": u["name"] if u["name"] != login else None,
                    "created": _iso(u["joined"]),
                    "packages": ", ".join(u["projects"][:10]) or None,
                },
                reason="PyPI serves a profile page for this username",
            )
        ]


# --- Chess.com and Lichess ------------------------------------------------------------------------


class ChessComAdapter(_Platform):
    name = "chesscom"
    label = "Chess.com"
    site = "Chess.com"
    description = "Chess.com's public API: a player's name, country, location and join date."
    health_check_target = "hikaru"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value).lower()
        data = await fetch_json(f"https://api.chess.com/pub/player/{quote(login)}", missing=(404, 410))
        if data is not None and (not isinstance(data, dict) or "username" not in data):
            raise SignatureMismatch("Chess.com returned an unexpected player record")
        return [RawResult(self.name, login, {"player": data})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        p = raw.payload["player"]
        if not p:
            return []
        login = p["username"]
        country = (p.get("country") or "").rstrip("/").rsplit("/", 1)[-1] or None
        return [
            api_account(
                "Chess.com",
                p.get("url") or f"https://www.chess.com/member/{login}",
                login,
                title=f"{p.get('name') or login} · Chess.com",
                profile={
                    "name": p.get("name"),
                    "location": p.get("location"),
                    "country": country,
                    "created": _iso(p.get("joined")),
                    "title": p.get("title"),
                },
            )
        ]


class LichessAdapter(_Platform):
    name = "lichess"
    label = "Lichess"
    site = "Lichess"
    description = "Lichess's API: a player's real name, bio, location, country and links, when they've filled them in."
    health_check_target = "thibault"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value)
        data = await fetch_json(f"https://lichess.org/api/user/{quote(login)}")
        if data is not None and (not isinstance(data, dict) or "id" not in data):
            raise SignatureMismatch("Lichess returned an unexpected user record")
        return [RawResult(self.name, login, {"user": data})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        u = raw.payload["user"]
        if not u or u.get("disabled") or u.get("closed"):
            return []
        prof = u.get("profile") or {}
        login = u.get("username") or u["id"]
        name = " ".join(
            x for x in (prof.get("realName") or "", prof.get("firstName") or "", prof.get("lastName") or "") if x
        ).strip()
        links, emails = profile_links(prof.get("bio") or "", prof.get("links") or "")
        return [
            api_account(
                "Lichess",
                u.get("url") or f"https://lichess.org/@/{login}",
                login,
                links=links,
                emails=emails,
                title=f"{name or login} · Lichess",
                profile={
                    "name": name or None,
                    "bio": _text(prof.get("bio")),
                    "location": prof.get("location"),
                    "country": prof.get("flag") or prof.get("country"),
                    "created": _iso(u.get("createdAt")),
                },
            )
        ]


# --- Codeberg -------------------------------------------------------------------------------------


class CodebergAdapter(_Platform):
    name = "codeberg"
    label = "Codeberg"
    site = "Codeberg"
    description = "Codeberg (Forgejo) API: the profile behind a username, with name, location, website and bio."
    health_check_target = "forgejo"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value)
        data = await fetch_json(f"https://codeberg.org/api/v1/users/{quote(login)}")
        if data is not None and (not isinstance(data, dict) or "login" not in data):
            raise SignatureMismatch("Codeberg returned an unexpected user record")
        return [RawResult(self.name, login, {"user": data})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        u = raw.payload["user"]
        if not u:
            return []
        login = u["login"]
        url = f"https://codeberg.org/{login}"
        site = _as_url(u.get("website") or "")
        links, emails = profile_links(u.get("description") or "")
        if u.get("email") and "@noreply." not in u["email"]:
            emails = sorted({*emails, u["email"].lower()})
        return [
            api_account(
                "Codeberg",
                url,
                login,
                links=[x for x in [site, *links] if x],
                emails=emails,
                title=f"{u.get('full_name') or login} · Codeberg",
                profile={
                    "name": u.get("full_name"),
                    "location": u.get("location"),
                    "bio": u.get("description"),
                    "created": _iso(u.get("created")),
                },
            )
        ] + [_email(e, "Codeberg profile", url, f"Codeberg '{login}'") for e in emails]


# --- Telegram -------------------------------------------------------------------------------------

_TG_TITLE = re.compile(r'<div class="tgme_page_title"[^>]*>\s*<span[^>]*>(.*?)</span>', re.S)
_TG_DESC = re.compile(r'<div class="tgme_page_description[^"]*"[^>]*>(.*?)</div>', re.S)
_TG_EXTRA = re.compile(r'<div class="tgme_page_extra">(.*?)</div>', re.S)


class TelegramAdapter(_Platform):
    name = "telegram"
    label = "Telegram"
    site = "Telegram"
    description = "Telegram's public t.me page for a username: the display name and bio of a user, channel or group."
    health_check_target = "durov"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        login = validate_handle(target_value)
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", login):
            return [RawResult(self.name, login, {"page": None})]  # not a valid Telegram username
        status, body = await fetch_page(f"https://t.me/{login}")
        if status != 200 or "tgme_" not in body:
            raise SignatureMismatch(f"t.me answered HTTP {status} without a Telegram page")
        title = _TG_TITLE.search(body)
        if not title:  # t.me serves a generic "contact" page for usernames nobody holds
            return [RawResult(self.name, login, {"page": None})]
        desc, extra = _TG_DESC.search(body), _TG_EXTRA.search(body)
        return [
            RawResult(
                self.name,
                login,
                {
                    "page": {
                        "name": _text(title.group(1)),
                        "bio": _text(desc.group(1)) if desc else "",
                        "extra": _text(extra.group(1)) if extra else "",
                    }
                },
            )
        ]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        p = raw.payload["page"]
        if not p:
            return []
        login = raw.target_value
        links, emails = profile_links(p["bio"])
        kind = "channel or group" if re.search(r"subscribers|members", p["extra"]) else "account"
        return [
            api_account(
                "Telegram",
                f"https://t.me/{login}",
                login,
                links=links,
                emails=emails,
                title=f"{p['name']} · Telegram",
                profile={"name": p["name"], "bio": p["bio"], "kind": kind, "audience": p["extra"] or None},
                reliability="C",
                reason="t.me serves a profile page for this username",
            )
        ]


PLATFORM_ADAPTERS = (
    RedditAdapter,
    BlueskyAdapter,
    MastodonAdapter,
    DockerHubAdapter,
    NpmAdapter,
    PyPIAdapter,
    ChessComAdapter,
    LichessAdapter,
    CodebergAdapter,
    TelegramAdapter,
)
