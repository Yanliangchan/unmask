"""Verification replay: page classification measured offline against labelled pages.

The live verifier fetches a profile URL and ``verify.classify`` decides what the page
proves: verified (the page is that profile), rejected (it is not), or unverified (it
can't tell: bot walls, login walls, a mention in passing). Sites change their error pages
all the time, so the classifier is the part most likely to drift. This replays pages
through it with no network and scores the verdicts.

Pages come from a deterministic generator built around the ways sites lie about whether a
profile exists (``KINDS``), or from a JSONL file of recorded pages in the same shape:

    {"url": "...", "username": "...", "status": 200, "final_url": "...", "page": "<html>...",
     "expected": "verified" | "rejected" | "unverified", "kind": "optional label"}

The metric that matters most is ``false_verified``: a page that is not the profile marked
as verifying it. That must stay at zero; a false "verified" is what puts a stranger's
account in a report.
"""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from app.verify import REJECTED, UNVERIFIED, VERIFIED, classify

SITES = ["forum.example", "art.example", "code.example", "photos.example", "music.example", "blog.example"]
HANDLES = ["mara_okafor", "tnovak", "ines.moreau", "kofi88", "hana-t", "ravi_haddad", "lenaq", "owen.varga"]


@dataclass
class Page:
    kind: str
    url: str
    username: str
    status: int
    final_url: str
    page: str
    expected: str


def _html(title: str, body: str, head: str = "") -> str:
    return f"<!doctype html><html><head><title>{title}</title>{head}</head><body>{body}</body></html>"


def _profile(site: str, user: str) -> tuple[int, str, str]:
    body = f"<nav><a href='https://{site}/'>Home</a></nav><h1>{user}</h1><p>Joined 2019. 41 posts.</p>"
    return 200, "", _html(f"{user} - Profile - {site}", body)


def _og_profile_with_widget(site: str, user: str) -> tuple[int, str, str]:
    head = f'<meta property="og:type" content="profile"><meta property="og:title" content="{user}">'
    body = f"<h1>{user}</h1><aside>Recommended: page not found? Try search.</aside>"
    return 200, "", _html(f"{user} on {site}", body, head)


def _hard_404(site: str, user: str) -> tuple[int, str, str]:
    return 404, "", _html("Not Found", "<h1>404</h1>")


def _soft_404_echo(site: str, user: str) -> tuple[int, str, str]:
    # Title echoes the requested name; the page itself says there is no such user.
    return 200, "", _html(f"{user} | {site}", "<h1>Sorry, this user doesn't exist.</h1><p>Check the spelling.</p>")


def _soft_404_title(site: str, user: str) -> tuple[int, str, str]:
    return 200, "", _html("Page not found", "<p>We looked everywhere.</p>")


def _login_redirect(site: str, user: str) -> tuple[int, str, str]:
    return 200, f"https://{site}/login?next=/{user}", _html("Log in", "<form><input name=password></form>")


def _home_redirect(site: str, user: str) -> tuple[int, str, str]:
    return 200, f"https://{site}/", _html(f"{site} - share what you make", "<p>Welcome.</p>")


def _bot_wall_status(site: str, user: str) -> tuple[int, str, str]:
    return 403, "", _html("Attention Required!", "<p>Checking your browser.</p>")


def _bot_wall_title(site: str, user: str) -> tuple[int, str, str]:
    return 200, "", _html("Just a moment...", "<p>Enable JavaScript and cookies to continue.</p>")


def _rate_limited(site: str, user: str) -> tuple[int, str, str]:
    return 429, "", _html("Too Many Requests", "<p>Slow down.</p>")


def _login_wall(site: str, user: str) -> tuple[int, str, str]:
    return 200, "", _html(f"Sign in to {site}", "<p>Create an account to see this page.</p>")


def _mention_only(site: str, user: str) -> tuple[int, str, str]:
    body = f"<h1>Weekly roundup</h1><p>Thanks to {user} for the tip.</p>"
    return 200, "", _html(f"Roundup - {site}", body)


def _unrelated(site: str, user: str) -> tuple[int, str, str]:
    return 200, "", _html(f"{site}", "<p>Trending today.</p>")


def _server_error(site: str, user: str) -> tuple[int, str, str]:
    return 500, "", _html("Error", "<p>Something went wrong.</p>")


# kind -> (builder, expected verdict, what it guards against)
KINDS = {
    "profile": (_profile, VERIFIED, "a real profile naming the user in its title"),
    "og_profile_widget": (_og_profile_with_widget, VERIFIED, "a profile whose sidebar says 'not found'"),
    "hard_404": (_hard_404, REJECTED, "HTTP 404"),
    "soft_404_echo": (_soft_404_echo, REJECTED, "an error page that repeats the requested name"),
    "soft_404_title": (_soft_404_title, REJECTED, "HTTP 200 with a 'not found' title"),
    "login_redirect": (_login_redirect, REJECTED, "redirected to a login page"),
    "home_redirect": (_home_redirect, REJECTED, "redirected to the home page"),
    "bot_wall_status": (_bot_wall_status, UNVERIFIED, "HTTP 403 bot protection"),
    "bot_wall_title": (_bot_wall_title, UNVERIFIED, "a JavaScript challenge page"),
    "rate_limited": (_rate_limited, UNVERIFIED, "HTTP 429"),
    "login_wall": (_login_wall, UNVERIFIED, "the profile shows only when signed in"),
    "mention_only": (_mention_only, UNVERIFIED, "the name appears on a page about something else"),
    "unrelated": (_unrelated, UNVERIFIED, "a page that does not mention the user"),
    "server_error": (_server_error, UNVERIFIED, "HTTP 500"),
}


def generate(per_kind: int = 6, seed: int = 20261021) -> list[Page]:
    rng = random.Random(seed)  # noqa: S311 — reproducible test data, not security
    pages = []
    for kind, (build, expected, _) in KINDS.items():
        for _ in range(per_kind):
            site, user = rng.choice(SITES), rng.choice(HANDLES)
            url = f"https://{site}/{user}"
            status, final, html = build(site, user)
            pages.append(Page(kind, url, user, status, final or url, html, expected))
    return pages


def load(path: str | Path) -> list[Page]:
    pages = []
    for n, line in enumerate(Path(path).read_text().splitlines(), 1):
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("expected") not in (VERIFIED, REJECTED, UNVERIFIED):
            raise ValueError(f"line {n}: expected must be verified, rejected or unverified")
        pages.append(Page(r.get("kind", "recorded"), r["url"], r["username"], int(r["status"]),
                          r.get("final_url") or r["url"], r["page"], r["expected"]))  # fmt: skip
    return pages


@dataclass
class Replay:
    kind: str
    url: str
    expected: str
    got: str
    reason: str


def replay(pages: list[Page]) -> list[Replay]:
    out = []
    for p in pages:
        v = classify(p.url, p.username, p.status, p.final_url, p.page)
        out.append(Replay(p.kind, p.url, p.expected, v.status, v.reason))
    return out


def report(results: list[Replay]) -> dict:
    confusion: dict[str, Counter] = defaultdict(Counter)
    kinds: dict[str, dict] = {}
    for r in results:
        confusion[r.expected][r.got] += 1
        k = kinds.setdefault(r.kind, {"n": 0, "wrong": 0})
        k["n"] += 1
        k["wrong"] += r.got != r.expected
    for kind, k in kinds.items():
        if kind in KINDS:
            k["about"] = KINDS[kind][2]
    false_verified = [asdict(r) for r in results if r.got == VERIFIED and r.expected != VERIFIED]
    right = sum(r.got == r.expected for r in results)
    return {
        "pages": len(results),
        "accuracy": round(right / len(results), 4) if results else None,
        "false_verified": len(false_verified),
        "false_verified_examples": false_verified[:5],
        # A real profile we failed to confirm: costs recall, not correctness.
        "missed_profiles": sum(1 for r in results if r.expected == VERIFIED and r.got != VERIFIED),
        "confusion": {e: dict(c) for e, c in confusion.items()},
        "kinds": kinds,
    }


def regressions(current: dict, baseline: dict) -> list[str]:
    problems = []
    if current["false_verified"] > 0:
        problems.append(f"{current['false_verified']} page(s) wrongly marked as verifying the profile")
    ca, ba = current["accuracy"] or 0, (baseline or {}).get("accuracy") or 0
    if ca < ba - 0.005:
        problems.append(f"page classification accuracy fell from {ba:.3f} to {ca:.3f}")
    return problems


def summary_lines(r: dict) -> list[str]:
    out = [
        f"Verification replay: {r['pages']} pages, accuracy {r['accuracy']}",
        f"  Wrongly verified: {r['false_verified']}   Real profiles not confirmed: {r['missed_profiles']}",
    ]
    out += [f"  {k:18} {v['wrong']:>3}/{v['n']:<3} {v.get('about', '')}" for k, v in r["kinds"].items() if v["wrong"]]
    return out
