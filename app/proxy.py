"""Optional outbound proxy for tools that sites block from cloud IP addresses.

Sites rate-limit or refuse data-centre IPs, which is why Holehe and parts of
Sherlock fail from a cloud host. With UNMASK_PROXY_URL set (for example a
residential proxy), the tools listed in UNMASK_PROXY_TOOLS send their traffic
through it. The URL is handed to tools through the environment (HTTPS_PROXY
and friends), never on the command line, so its credentials don't show up in
process listings or logs.

"verify" in the list means the profile-page check (app/verify.py).
"""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit

from app.config import get_settings


def proxy_tools() -> set[str]:
    raw = get_settings().proxy_tools.strip().lower()
    return {t.strip() for t in raw.split(",") if t.strip()}


def proxy_for(tool: str) -> str | None:
    s = get_settings()
    if not s.proxy_url:
        return None
    tools = proxy_tools()
    return s.proxy_url if ("all" in tools or tool.lower() in tools) else None


def proxy_env(tool: str) -> dict[str, str]:
    """Environment variables that route a child process through the proxy (empty if none)."""
    url = proxy_for(tool)
    if not url:
        return {}
    return {"HTTP_PROXY": url, "HTTPS_PROXY": url, "http_proxy": url, "https_proxy": url}


def masked(url: str) -> str:
    """The proxy URL with its password hidden, for display."""
    parts = urlsplit(url)
    if parts.password:
        netloc = f"{parts.username}:••••@{parts.hostname}" + (f":{parts.port}" if parts.port else "")
        return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))


def describe() -> str | None:
    s = get_settings()
    if not s.proxy_url:
        return None
    tools = ", ".join(sorted(proxy_tools())) or "no tools"
    return f"{masked(s.proxy_url)} for {tools}"
