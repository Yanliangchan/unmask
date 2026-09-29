"""Tool failures explained in plain words, with what to do."""

import uuid

import pytest

from app import jobs
from app.config import get_settings
from app.services.failures import explain
from tests.conftest import case_form_data, login


@pytest.mark.parametrize(
    ("error", "says", "retry", "fix"),
    [
        ("holehe is not installed", "isn't installed", False, "tools"),
        ("No API key configured (UNMASK_BRAVE_API_KEY)", "needs an API key", False, "tools"),
        ("Auto-disabled after 4 consecutive failures: HTTP 503", "switched off", False, "tools"),
        ("4/4 input(s) failed: 116/117 sites rate-limited or errored", "refused the server's requests", True, "proxy"),
        ("request failed: ProxyError: 403 Forbidden", "couldn't connect to its sites", True, None),
        ("maigret timed out after 900s", "took too long", True, None),
        ("sherlock did not report completion (run was cut short)", "doesn't look like a complete run", True, None),
        ("something nobody anticipated", "failed, so its results are missing", True, None),
    ],
)
def test_explanations(error, says, retry, fix):
    x = explain("holehe", error)
    assert says in x.summary and x.retry is retry and x.fix == fix


def test_proxy_errors_point_at_the_configured_proxy(monkeypatch):
    monkeypatch.setattr(get_settings(), "proxy_url", "http://proxy.example:8080")
    x = explain("holehe", "request failed: ProxyError: 407")
    assert "through the proxy" in x.summary and x.fix == "proxy"


def test_blocked_hint_changes_once_a_proxy_is_set(monkeypatch):
    monkeypatch.setattr(get_settings(), "proxy_url", "http://proxy.example:8080")
    x = explain("holehe", "117/117 sites rate-limited")
    assert "proxy's address may be blocked" in x.hint and x.fix is None


async def test_scan_status_explains_the_failure_and_offers_a_retry(client, db):
    from sqlalchemy import text

    # Earlier tests may have tripped fake_fail's circuit breaker.
    await db.execute(text("UPDATE tool_config SET enabled = true, consecutive_failures = 0, circuit_open = false"))
    await db.commit()
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"F {uuid.uuid4().hex[:6]}"))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    status = (await client.get(f"/cases/{case_id}/scan-status")).text
    assert "Fake Fail failed, so its results are missing" in status
    assert "upstream returned HTTP 503" in status  # the raw detail is still there
    assert "Retry Fake Fail" in status and '"only": "fake_fail"' in status
