"""Shared HTTP client for API-backed adapters."""

from __future__ import annotations

import httpx

from app.adapters.base import AdapterError, SignatureMismatch

USER_AGENT = "unmask-osint/0.2"

# Tests swap this for an httpx.MockTransport.
transport: httpx.AsyncBaseTransport | None = None


def client(timeout: float = 60) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=transport,
        timeout=timeout,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        follow_redirects=False,
    )


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
