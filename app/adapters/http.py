"""Shared HTTP client for API-backed adapters."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from app.adapters.base import AdapterError, SignatureMismatch

USER_AGENT = "unmask-osint/0.2"

# Tests swap this for an httpx.MockTransport.
transport: httpx.AsyncBaseTransport | None = None


# One pooled client per event loop and timeout: API adapters hit the same few
# hosts (api.github.com, ...) many times a scan, and a fresh client per request
# repeats the TLS handshake each time. Closed with close_clients().
_pool: dict[tuple, httpx.AsyncClient] = {}


def _pooled(timeout: float) -> httpx.AsyncClient:
    key = (id(asyncio.get_running_loop()), float(timeout), transport)
    c = _pool.get(key)
    if c is None or c.is_closed:
        c = _pool[key] = httpx.AsyncClient(
            transport=transport,
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
            follow_redirects=False,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10, keepalive_expiry=30),
        )
    return c


@asynccontextmanager
async def client(timeout: float = 60) -> AsyncIterator[httpx.AsyncClient]:  # noqa: ASYNC109
    """A shared, pooled client; leaving the block does not close it."""
    yield _pooled(timeout)


async def close_clients() -> None:
    loop_id = id(asyncio.get_running_loop())
    for key in [k for k in _pool if k[0] == loop_id]:
        await _pool.pop(key).aclose()


async def post_json(
    url: str,
    *,
    body: dict,
    headers: dict | None = None,
    timeout: float = 60,  # noqa: ASYNC109 — passed through to httpx
) -> tuple[httpx.Response, object]:
    """POST a JSON body to a JSON API; the same "a non-JSON 200 is an error" rule as get_json."""
    try:
        async with client(timeout) as c:
            resp = await c.post(url, json=body, headers=headers)
    except httpx.HTTPError as exc:
        raise AdapterError(f"request failed: {exc.__class__.__name__}: {exc}") from exc
    if resp.status_code != 200:
        raise AdapterError(f"HTTP {resp.status_code} from {resp.url.host}")
    try:
        return resp, resp.json()
    except ValueError as exc:
        raise SignatureMismatch(f"{resp.url.host} returned a body that isn't JSON") from exc


async def get_json(
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float = 60,  # noqa: ASYNC109 — passed through to httpx
    strict_content_type: bool = True,
) -> tuple[httpx.Response, object]:
    """GET a JSON endpoint; anything that isn't a JSON 200 is an error, never "no data".

    ``strict_content_type=False`` is for APIs that serve JSON under another
    type (DuckDuckGo uses application/x-javascript); the body must still parse.
    """
    try:
        async with client(timeout) as c:
            resp = await c.get(url, params=params, headers=headers)
    except httpx.HTTPError as exc:
        raise AdapterError(f"request failed: {exc.__class__.__name__}: {exc}") from exc
    if resp.status_code != 200:
        raise AdapterError(f"HTTP {resp.status_code} from {resp.url.host}")
    ctype = resp.headers.get("content-type", "")
    if strict_content_type and "json" not in ctype:
        raise SignatureMismatch(
            f"{resp.url.host} answered 200 with {ctype or 'no content type'} instead of JSON "
            "(likely an error or bot-check page)"
        )
    try:
        return resp, resp.json()
    except ValueError as exc:
        raise SignatureMismatch(
            f"{resp.url.host} returned a body that isn't JSON (likely an error or bot-check page)"
        ) from exc
