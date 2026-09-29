"""Only the subject's own accounts count, and tools that can't work here aren't offered."""

from app.adapters.base import EntityCandidate, RawResult
from app.adapters.holehe import HoleheAdapter
from app.adapters.sherlock import SherlockAdapter
from app.adapters.websearch import WebSearchAdapter
from app.config import get_settings
from app.search.profiles import handle_relates_to
from app.verify import extract_links, is_site_account
from tests.conftest import login

PROFILE_PAGE = """<html><header><nav><a href="https://x.com/somebrand">X</a></nav></header>
<main><p>Hi, I'm Yan. <a href="https://x.com/yanliangchan">my X</a> <a href="https://github.com/yanliangchan">code</a>
<a href="https://x.com/realtryhackme">follow us</a></p></main>
<footer><a href="https://www.youtube.com/@tryhackme">YouTube</a><a href="https://x.com/anotherbrand">X</a></footer></html>"""


def test_profile_pages_link_the_person_not_the_site():
    links, _ = extract_links(PROFILE_PAGE, "https://tryhackme.com/p/yanliangchan", "yanliangchan")
    assert links == ["https://x.com/yanliangchan", "https://github.com/yanliangchan"]
    # A personal site named after the person keeps its own link.
    links, _ = extract_links('<a href="https://x.com/janedoe">me</a>', "https://janedoe.com/", "janedoe")
    assert links == ["https://x.com/janedoe"]
    assert is_site_account("github", "github.com") and not is_site_account("yanliangchan", "tryhackme.com", "x.com")


def test_handles_must_resemble_the_target():
    assert handle_relates_to("yanliangchan", "yanliangchan")
    assert handle_relates_to("yan_liang_chan", "Yan Liang Chan") and handle_relates_to("jdoe", "Jane Doe")
    assert handle_relates_to("jane.doe", "jane.doe@example.com")
    assert not handle_relates_to("realtryhackme", "yanliangchan")
    assert not handle_relates_to("acmecorp", "Jane Doe")


def test_web_search_keeps_company_profiles_as_mentions_not_accounts():
    hits = [
        {"url": "https://x.com/realtryhackme", "title": "TryHackMe", "snippet": "", "found_by": ["tags"], "rank": 1},
        {"url": "https://x.com/yanliangchan", "title": "Yan", "snippet": "", "found_by": ["exact"], "rank": 2},
    ]
    raw = RawResult("websearch", "yanliangchan", {"provider": "Serper", "queries": [], "failed": [], "hits": hits})
    cands = WebSearchAdapter().parse(raw)
    assert [c.value for c in cands if c.type == "account"] == ["https://x.com/yanliangchan"]
    assert {c.attributes["url"] for c in cands if c.type == "web_mention"} == {h["url"] for h in hits}


def test_sherlock_health_passes_when_one_signature_site_is_blocked():
    gh = EntityCandidate("account", "https://github.com/torvalds", {"site": "GitHub"})
    result = SherlockAdapter().check_health_output([gh])
    assert result.ok and "GitLab" in result.detail
    assert not SherlockAdapter().check_health_output([]).ok


def test_holehe_needs_a_proxy_on_a_server(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "proxy_url", "")
    monkeypatch.setattr(s, "holehe_direct", False)
    assert "needs a proxy" in HoleheAdapter().configured()
    monkeypatch.setattr(s, "proxy_url", "http://user:pass@proxy.example:8080")
    monkeypatch.setattr(s, "proxy_tools", "holehe")
    assert HoleheAdapter().configured() is None
    monkeypatch.setattr(s, "proxy_url", "")
    monkeypatch.setattr(s, "holehe_direct", True)
    assert HoleheAdapter().configured() is None


async def test_unconfigured_tools_are_not_offered_even_after_tripping_the_breaker(client, db, monkeypatch):
    from app.adapters import registry
    from app.models import ToolConfig
    from app.services.tools import sync_tool_config

    s = get_settings()
    monkeypatch.setattr(s, "proxy_url", "")
    monkeypatch.setattr(s, "holehe_direct", False)
    registry.register(HoleheAdapter())
    try:
        await sync_tool_config(db)
        cfg = await db.get(ToolConfig, "holehe")
        cfg.circuit_open, cfg.consecutive_failures = True, 3
        await db.commit()
        await login(client)
        assert 'value="holehe"' not in (await client.get("/cases/new")).text
        tools = (await client.get("/tools")).text
        assert "available once set up" in tools and "needs a proxy" in tools and "Circuit open" not in tools
    finally:
        registry.unregister("holehe")
