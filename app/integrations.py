"""Integrations: the API keys and connection settings lookup tools need, managed in the app.

An administrator enters keys on the Integrations page. They are stored
encrypted (``app_secrets``) and laid over the matching settings, so every
adapter keeps reading ``get_settings()`` as before. A value set in the app
wins over the environment variable; removing it falls back to the variable.

Each process refreshes its copy at startup, after a change, before a scan or
health check runs, and at most a minute apart otherwise, so a key entered in
the web app reaches the scan workers without a restart.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings


@dataclass(frozen=True)
class KeyField:
    setting: str  # attribute on Settings
    label: str
    secret: bool = True
    placeholder: str = ""
    help: str = ""
    max_length: int = 500


@dataclass(frozen=True)
class Integration:
    key: str
    label: str
    category: str
    adds: str  # what it contributes to a case
    cost: str  # free tier, in a few words
    signup: str  # where to get a key
    fields: tuple[KeyField, ...]
    tools: tuple[str, ...] = ()  # adapters that use it
    optional: bool = False  # the tools work without it, just better with it
    notes: list[str] = field(default_factory=list)


CATALOG: list[Integration] = [
    # --- Web search ------------------------------------------------------------------------
    Integration(
        "serper", "Serper (Google results)", "Web search",
        "Targeted Google searches for every target, the Web tab, and profiles found by search.",
        "2,500 free searches, then paid", "https://serper.dev/api-key",
        (KeyField("serper_key", "API key"),), ("websearch",),
        notes=["Only one search provider is used: the first one with a key, in the order listed here."],
    ),
    Integration(
        "serpapi", "SerpAPI", "Web search", "An alternative Google results provider for the same searches.",
        "100 free searches a month", "https://serpapi.com/manage-api-key",
        (KeyField("serpapi_key", "API key"),), ("websearch",),
    ),
    Integration(
        "google", "Google Programmable Search", "Web search", "Google's own search API for the same searches.",
        "100 free searches a day", "https://developers.google.com/custom-search/v1/overview",
        (KeyField("google_api_key", "API key"),
         KeyField("google_cx", "Search engine ID (cx)", secret=False, placeholder="e.g. 0123456789abcdef0")),
        ("websearch",),
    ),
    Integration(
        "brave", "Brave Search", "Web search", "Independent search index for the same searches.",
        "2,000 free searches a month", "https://api-dashboard.search.brave.com/",
        (KeyField("brave_api_key", "API key"),), ("websearch",),
    ),
    # --- People and accounts -----------------------------------------------------------------
    Integration(
        "github", "GitHub", "Accounts",
        "GitHub lookups work without it; a token raises the limit from 60 to 5,000 an hour, which email lookups "
        "(finding who committed with an address) quickly need.",
        "Free (a personal access token with no scopes)", "https://github.com/settings/personal-access-tokens/new",
        (KeyField("github_token", "Personal access token", placeholder="github_pat_…"),), ("github",), optional=True,
    ),
    Integration(
        "hunter", "Hunter", "Accounts",
        "Email addresses published for a domain's people, with their names and roles.",
        "25 free searches a month", "https://hunter.io/api-keys",
        (KeyField("hunter_key", "API key"),), ("hunter",),
    ),
    Integration(
        "emailrep", "EmailRep", "Accounts",
        "An email address's reputation: how long it has existed, profiles it's tied to, whether it's disposable.",
        "Free key on request", "https://emailrep.io/key",
        (KeyField("emailrep_key", "API key"),), ("emailrep",),
    ),
    # --- Breaches ------------------------------------------------------------------------------
    Integration(
        "hibp", "Have I Been Pwned", "Breaches",
        "Which known data breaches an email address appears in, with dates and what was exposed.",
        "Paid, from about US$4 a month", "https://haveibeenpwned.com/API/Key",
        (KeyField("hibp_key", "API key"),), ("hibp",),
    ),
    Integration(
        "h8mail", "h8mail breach sources", "Breaches",
        "Extra breach sources for h8mail, one per line, e.g. snusbase_token=…, leak-lookup_priv=…, intelx_key=….",
        "Depends on the source", "https://github.com/khast3x/h8mail#apis",
        (KeyField("h8mail_keys", "Keys (name=value, one per line or comma-separated)", max_length=4000),), ("h8mail",),
    ),
    # --- Infrastructure ------------------------------------------------------------------------
    Integration(
        "shodan", "Shodan", "Infrastructure",
        "Open ports, services and hostnames seen on an IP address.",
        "Free account includes a key with limited credits", "https://account.shodan.io/",
        (KeyField("shodan_key", "API key"),), ("shodan",),
    ),
    Integration(
        "ipinfo", "IPinfo", "Infrastructure",
        "Location, network owner and hostname of an IP address. Works without a token, more reliably with one.",
        "50,000 free lookups a month", "https://ipinfo.io/signup",
        (KeyField("ipinfo_token", "Access token"),), ("ipinfo",), optional=True,
    ),
    Integration(
        "virustotal", "VirusTotal", "Infrastructure",
        "Subdomains and the IP addresses a domain has pointed to (passive DNS).",
        "500 free lookups a day", "https://www.virustotal.com/gui/my-apikey",
        (KeyField("virustotal_key", "API key"),), ("virustotal",),
    ),
    Integration(
        "securitytrails", "SecurityTrails", "Infrastructure",
        "A domain's subdomains and its DNS records over time.",
        "50 free lookups a month", "https://securitytrails.com/app/account/credentials",
        (KeyField("securitytrails_key", "API key"),), ("securitytrails",),
    ),
    # --- Phone ---------------------------------------------------------------------------------
    Integration(
        "numverify", "Numverify", "Phone",
        "Whether a phone number is valid, its country, carrier and line type (mobile or landline).",
        "100 free lookups a month", "https://numverify.com/product",
        (KeyField("numverify_key", "API key"),), ("numverify",),
    ),
    # --- Network ---------------------------------------------------------------------------------
    Integration(
        "proxy", "Outbound proxy", "Network",
        "Routes tools that sites block from cloud servers (Holehe, Sherlock, Maigret, profile checks) through a proxy. "
        "A residential proxy works best.",
        "Paid (from any residential proxy provider)", "https://github.com/topics/residential-proxy",
        (KeyField("proxy_url", "Proxy URL", placeholder="http://user:password@host:port or socks5://…"),),
        ("holehe", "sherlock", "maigret"),
    ),
]  # fmt: skip

BY_KEY = {i.key: i for i in CATALOG}
MANAGED: dict[str, KeyField] = {f.setting: f for i in CATALOG for f in i.fields}
CATEGORIES = ["Web search", "Accounts", "Breaches", "Infrastructure", "Phone", "Network"]

REFRESH_SECONDS = 60
_env_defaults: dict[str, str] | None = None
_stored: dict[str, str] = {}
_loaded_at = 0.0


def _defaults() -> dict[str, str]:
    """The environment's values, captured before the app's own override anything."""
    global _env_defaults
    if _env_defaults is None:
        s = get_settings()
        _env_defaults = {name: str(getattr(s, name, "") or "") for name in MANAGED}
    return _env_defaults


def apply(values: dict[str, str]) -> None:
    """Lay stored values over the settings; a value removed from the app falls back to the environment.

    Only settings whose stored value changed are touched, so nothing else that
    set a value at runtime is overwritten by a routine refresh.
    """
    global _stored
    defaults = _defaults()
    s = get_settings()
    new = {k: v for k, v in values.items() if k in MANAGED and v}
    for name in MANAGED:
        if new.get(name) != _stored.get(name):
            setattr(s, name, new.get(name, defaults[name]))
    _stored = new


async def refresh(session: AsyncSession | None = None, *, force: bool = False) -> None:
    """Reload stored values from the database (at most once a minute unless forced)."""
    global _loaded_at
    if not force and time.monotonic() - _loaded_at < REFRESH_SECONDS:
        return
    from app.models import AppSecret

    async def load(s: AsyncSession) -> dict[str, str]:
        return {row.name: row.value for row in (await s.scalars(select(AppSecret))).all()}

    try:
        if session is not None:
            values = await load(session)
        else:
            from app.db import sessionmaker

            async with sessionmaker()() as s:
                values = await load(s)
    except Exception:  # the table may not exist yet mid-deploy: keep what we have
        return
    _loaded_at = time.monotonic()
    apply(values)


def source_of(setting: str) -> str | None:
    """Where a setting's current value comes from: "app", "environment", or None if unset."""
    if _stored.get(setting):
        return "app"
    if _defaults().get(setting):
        return "environment"
    return None


def masked(setting: str) -> str:
    value = str(getattr(get_settings(), setting, "") or "")
    if not value:
        return ""
    if not MANAGED[setting].secret:
        return value
    if setting == "proxy_url":
        from app.proxy import masked as mask_proxy

        return mask_proxy(value)
    return "•" * 6 + value[-4:] if len(value) > 8 else "•" * 6


def is_set(integration: Integration) -> bool:
    return all(getattr(get_settings(), f.setting, "") for f in integration.fields)
