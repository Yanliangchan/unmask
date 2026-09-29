"""The optional outbound proxy."""

import pytest

from app import proxy
from app.adapters.base import run_tool_subprocess
from app.config import get_settings


@pytest.fixture
def with_proxy(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "proxy_url", "http://alice:s3cret@proxy.example:8080")
    monkeypatch.setattr(s, "proxy_tools", "holehe, verify")
    return s


def test_proxy_applies_only_to_listed_tools(with_proxy, monkeypatch):
    assert proxy.proxy_for("holehe") == "http://alice:s3cret@proxy.example:8080"
    assert proxy.proxy_for("sherlock") is None
    monkeypatch.setattr(with_proxy, "proxy_tools", "all")
    assert proxy.proxy_for("sherlock")
    monkeypatch.setattr(with_proxy, "proxy_url", "")
    assert proxy.proxy_for("holehe") is None and proxy.describe() is None


def test_proxy_password_is_never_displayed(with_proxy):
    assert proxy.describe() == "http://alice:••••@proxy.example:8080 for holehe, verify"
    assert proxy.masked("socks5://proxy.example:1080") == "socks5://proxy.example:1080"


async def test_tools_get_the_proxy_through_the_environment_not_argv(with_proxy):
    argv = ["sh", "-c", "echo HTTPS=$HTTPS_PROXY; echo https=$https_proxy"]
    listed = await run_tool_subprocess(argv, tool="holehe")
    assert "HTTPS=http://alice:s3cret@proxy.example:8080" in listed.stdout
    assert "https=http://alice:s3cret@proxy.example:8080" in listed.stdout
    other = await run_tool_subprocess(argv, tool="sherlock")
    assert "alice" not in other.stdout


async def test_tools_page_shows_the_proxy_masked(client, with_proxy):
    from tests.conftest import login

    await login(client)
    page = (await client.get("/tools")).text
    assert "alice:••••@proxy.example:8080" in page and "s3cret" not in page
