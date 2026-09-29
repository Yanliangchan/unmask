"""Tool failures in plain words, with what to do about them.

Adapters report exactly what went wrong ("116/117 sites rate-limited or
errored", "HTTP 403 from google.serper.dev"). That detail is kept, but the
first thing an analyst reads is what it means for the case and what they
can do: retry later, set a proxy, add a key, or look at the Tools page.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.config import get_settings


@dataclass(frozen=True)
class Explanation:
    summary: str
    hint: str
    # A retry has a real chance of working (a timeout, a temporary block).
    retry: bool = True
    # Where the fix lives, if it's a setting rather than a retry.
    fix: str | None = None


_RULES: list[tuple[re.Pattern, callable]] = []


def _rule(pattern: str):
    def register(fn):
        _RULES.append((re.compile(pattern, re.I), fn))
        return fn

    return register


@_rule(r"not installed|No such file")
def _missing(tool, error):
    return Explanation(
        f"{tool} isn't installed on the server.",
        "The Docker image installs every tool; a local setup needs scripts/install-tools.sh.",
        retry=False,
        fix="tools",
    )


@_rule(r"api key|not configured|UNMASK_[A-Z_]+_KEY")
def _key(tool, error):
    return Explanation(
        f"{tool} needs an API key before it can run.",
        "Add the key named in the details as a service variable, then run the scan again.",
        retry=False,
        fix="tools",
    )


@_rule(r"circuit|auto-disabled|consecutive failure")
def _breaker(tool, error):
    return Explanation(
        f"{tool} was switched off after failing several times in a row.",
        "Run its check on the Tools page; it switches back on as soon as a check passes.",
        retry=False,
        fix="tools",
    )


@_rule(r"ProxyError|proxy")
def _proxy(tool, error):
    if get_settings().proxy_url:
        return Explanation(
            f"{tool} couldn't reach its sites through the proxy.",
            "Check UNMASK_PROXY_URL (address, port, credentials) and that the proxy is up.",
            fix="proxy",
        )
    # Not our proxy: the server's own network path refused the connection.
    return Explanation(
        f"{tool} couldn't connect to its sites from this server.",
        "The server's network blocked the request. Retry later; if it persists, check the host's outbound network.",
    )


@_rule(r"rate.?limit|blocked|bot.?(?:check|wall|detection)|captcha|\b403\b|\b429\b|forbidden|too many requests")
def _blocked(tool, error):
    proxy = get_settings().proxy_url
    return Explanation(
        f"The sites {tool} checks refused the server's requests, so its results are incomplete.",
        "This is common from cloud servers. Try again later"
        + (
            "; a proxy is already set, so the proxy's address may be blocked too."
            if proxy
            else ", or route the tool through a proxy (UNMASK_PROXY_URL)."
        ),  # fmt: skip
        fix=None if proxy else "proxy",
    )


@_rule(r"timed out|timeout")
def _timeout(tool, error):
    return Explanation(
        f"{tool} took too long and was stopped.",
        "Sites may be slow right now. Retry, or use a Quick scan to skip the slowest tools.",
    )


@_rule(r"invalid target|only contain|is not a plain")
def _invalid(tool, error):
    return Explanation(
        f"{tool} can't use this target value.",
        "Check the target's type and spelling; nothing was searched with it.",
        retry=False,
    )


@_rule(r"cut short|did not report completion|missing its start banner|not valid|isn't JSON|signature")
def _garbled(tool, error):
    return Explanation(
        f"{tool} returned output that doesn't look like a complete run, so it was not trusted.",
        "Often a site change or a blocked request. Retry; if it keeps happening, "
        "run the tool's check on the Tools page.",
    )


@_rule(r"stopped by")
def _stopped(tool, error):
    return Explanation("The scan was stopped.", "Findings reported before the stop are kept.", retry=False)


def explain(tool: str, error: str) -> Explanation:
    """The first matching rule's explanation; unknown errors still get an honest default."""
    from app.adapters.registry import get_adapter

    adapter = get_adapter(tool)
    label = adapter.label if adapter else tool
    for pattern, fn in _RULES:
        if pattern.search(error or ""):
            return fn(label, error)
    return Explanation(f"{label} failed, so its results are missing from this scan.", "Retry the tool.")
