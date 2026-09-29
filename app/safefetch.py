"""Fetch a public web page for the analyst, without letting the URL reach inside the network.

The URL can come from an analyst or from a search result, so every hop is
checked before it is requested: http(s) only, standard ports, and a host
name that resolves to public addresses only (no loopback, private ranges,
link-local cloud metadata, and so on). Redirects are followed by hand so
each one is checked the same way.

What remains is DNS rebinding between the check and the request; routing
fetches through UNMASK_PROXY_URL moves resolution to the proxy.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import httpx

MAX_BYTES = 2_000_000
MAX_REDIRECTS = 5
ALLOWED_PORTS = {None, 80, 443, 8080, 8443}
HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.5",
    "Accept-Language": "en;q=0.8",
}

# Tests swap these: an httpx.MockTransport, and a resolver that doesn't touch the network.
transport: httpx.AsyncBaseTransport | None = None


def _resolve(host: str) -> list[str]:
    return [info[4][0] for info in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)]


resolver = _resolve


class BlockedURL(ValueError):
    pass


@dataclass
class Page:
    url: str
    final_url: str
    status_code: int
    content_type: str
    body: bytes
    truncated: bool


async def check_url(url: str) -> None:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise BlockedURL("Only http and https pages can be captured")
    if not parts.hostname:
        raise BlockedURL("The address has no host")
    try:
        port = parts.port
    except ValueError:
        raise BlockedURL("The address has an invalid port") from None
    if port not in ALLOWED_PORTS:
        raise BlockedURL("Only standard web ports can be captured")
    host = parts.hostname
    try:
        addresses = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            addresses = [ipaddress.ip_address(a.split("%")[0]) for a in await asyncio.to_thread(resolver, host)]
        except OSError:
            raise BlockedURL(f"{host} could not be resolved") from None
    if not addresses or not all(a.is_global for a in addresses):
        raise BlockedURL("That address is not on the public internet")


async def fetch(url: str, *, proxy: str | None = None, time_limit: float = 15) -> Page:
    current = url
    async with httpx.AsyncClient(
        transport=transport, proxy=proxy if transport is None else None, headers=HEADERS, timeout=time_limit,
        follow_redirects=False,
    ) as client:  # fmt: skip
        for _ in range(MAX_REDIRECTS + 1):
            await check_url(current)
            async with client.stream("GET", current) as resp:
                if resp.is_redirect and resp.headers.get("location"):
                    current = urljoin(current, resp.headers["location"])
                    continue
                chunks, size, truncated = [], 0, False
                async for chunk in resp.aiter_bytes():
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_BYTES:
                        truncated = True
                        break
                return Page(url, current, resp.status_code, resp.headers.get("content-type", ""),
                            b"".join(chunks)[:MAX_BYTES], truncated)  # fmt: skip
    raise BlockedURL("Too many redirects")
