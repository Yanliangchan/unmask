"""Recognise profile URLs on well-known sites.

Used to turn a search result or a link on someone's profile page into an
account ("GitHub · janedoe") instead of a bare web page, so it can be checked,
scored and cross-linked like any other account.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

_HANDLE = r"(?P<h>[A-Za-z0-9][A-Za-z0-9._\-]{0,62})"

# (site label, host pattern, path pattern, words that are pages rather than people)
_RULES: list[tuple[str, str, str, str]] = [
    ("GitHub", r"(?:www\.)?github\.com", rf"^/{_HANDLE}/?$",
     "about features topics orgs marketplace pricing login join sponsors settings explore collections trending "
     "events enterprise security readme site apps"),
    ("GitLab", r"(?:www\.)?gitlab\.com", rf"^/{_HANDLE}/?$", "explore users help dashboard groups"),
    ("X", r"(?:www\.|mobile\.)?(?:x|twitter)\.com", rf"^/{_HANDLE}/?$",
     "i home search explore intent share hashtag login signup settings tos privacy messages notifications"),
    ("Instagram", r"(?:www\.)?instagram\.com", rf"^/{_HANDLE}/?$",
     "p reel reels explore stories accounts about direct tv"),
    ("Facebook", r"(?:www\.|m\.)?facebook\.com", rf"^/{_HANDLE}/?$",
     "pages groups events watch marketplace login help profile.php public people"),
    ("LinkedIn", r"(?:[a-z]{2,3}\.|www\.)?linkedin\.com", rf"^/in/{_HANDLE}/?$", ""),
    ("TikTok", r"(?:www\.)?tiktok\.com", rf"^/@{_HANDLE}/?$", ""),
    ("Reddit", r"(?:www\.|old\.)?reddit\.com", rf"^/(?:u|user)/{_HANDLE}/?$", ""),
    ("Medium", r"(?:www\.)?medium\.com", rf"^/@{_HANDLE}/?$", ""),
    ("YouTube", r"(?:www\.|m\.)?youtube\.com", rf"^/@{_HANDLE}/?$", ""),
    ("Telegram", r"t\.me", rf"^/{_HANDLE}/?$", "s joinchat addstickers share"),
    ("Keybase", r"keybase\.io", rf"^/{_HANDLE}/?$", "docs blog download jobs"),
    ("Twitch", r"(?:www\.)?twitch\.tv", rf"^/{_HANDLE}/?$", "directory downloads p search settings"),
    ("Pinterest", r"(?:[a-z]{2}\.|www\.)?pinterest\.com", rf"^/{_HANDLE}/?$", "pin search ideas today"),
    ("Stack Overflow", r"(?:www\.)?stackoverflow\.com", rf"^/users/\d+/{_HANDLE}/?$", ""),
    ("Hacker News", r"news\.ycombinator\.com", r"^/user$", ""),
]  # fmt: skip
_COMPILED = [
    (site, re.compile(f"^{host}$", re.I), re.compile(path), set(stop.split())) for site, host, path, stop in _RULES
]


@dataclass(frozen=True)
class Profile:
    site: str
    handle: str
    url: str


def match_profile(url: str) -> Profile | None:
    """Return the site and handle if ``url`` is a person's profile page on a known site."""
    try:
        parsed = urlparse(url.strip())
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    for site, host, path, stop in _COMPILED:
        if not host.match(parsed.hostname):
            continue
        if site == "Hacker News":
            m = re.search(r"(?:^|&)id=([A-Za-z0-9_\-]{2,15})(?:&|$)", parsed.query)
            if parsed.path == "/user" and m:
                return Profile(site, m.group(1), f"https://news.ycombinator.com/user?id={m.group(1)}")
            return None
        m = path.match(parsed.path)
        if not m or m.group("h").lower() in stop:
            return None
        canonical = f"https://{parsed.hostname.lower()}{parsed.path.rstrip('/')}"
        return Profile(site, m.group("h"), canonical)
    return None


def is_known_site(url: str) -> bool:
    """True for any page on a site listed here, profile or not (share buttons, search pages...)."""
    host = (urlparse(url).hostname or "").lower()
    return any(h.match(host) for _, h, _, _ in _COMPILED)
