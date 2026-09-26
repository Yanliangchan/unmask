"""Operational alerts to a webhook (Slack/Discord/Teams-compatible ``{"text": ...}``).

Best effort: an unreachable webhook is logged, never allowed to break a scan.
Alert text never includes case data — only tool names and counts.
"""

from __future__ import annotations

import logging

import httpx

from app.config import get_settings

log = logging.getLogger(__name__)

# Tests swap this for an httpx.MockTransport.
transport: httpx.AsyncBaseTransport | None = None


async def send_alert(text: str) -> bool:
    url = get_settings().alert_webhook_url
    if not url:
        return False
    try:
        async with httpx.AsyncClient(transport=transport, timeout=10) as client:
            resp = await client.post(url, json={"text": f"[unmask] {text}"})
            resp.raise_for_status()
        return True
    except httpx.HTTPError as exc:
        log.warning("alert webhook failed: %s", exc)
        return False
