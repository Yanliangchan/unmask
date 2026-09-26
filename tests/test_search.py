import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from app.adapters import http
from app.adapters.base import InvalidTarget, SignatureMismatch
from app.adapters.websearch import BraveSearchAdapter, DuckDuckGoAdapter, build_query
from app.config import get_settings
from app.search_links import search_links


@pytest.fixture
def mock_http():
    calls = []

    def install(handler):
        def wrapped(request):
            calls.append(request)
            return handler(request)

        http.transport = httpx.MockTransport(wrapped)
        return calls

    yield install
    http.transport = None


def test_query_is_an_exact_phrase_narrowed_by_two_tags():
    assert build_query('Yan "Liang" Chan', ["singapore", "fintech", "extra"]) == '"Yan Liang Chan" singapore fintech'
    with pytest.raises(InvalidTarget):
        build_query("  ", [])


# --- Brave ------------------------------------------------------------------------------


def test_brave_is_not_configured_without_a_key(monkeypatch):
    monkeypatch.setattr(get_settings(), "brave_api_key", "")
    assert "UNMASK_BRAVE_API_KEY" in BraveSearchAdapter().configured()


async def test_brave_parses_results_and_sends_the_key_as_a_header(mock_http, monkeypatch):
    monkeypatch.setattr(get_settings(), "brave_api_key", "k-123")
    monkeypatch.setattr(get_settings(), "brave_max_results", 20)
    body = {
        "type": "search",
        "query": {"more_results_available": False},
        "web": {"results": [
            {"url": "https://example.org/team", "title": "Team", "description": "Yan Liang Chan, Singapore"},
            {"url": "javascript:alert(1)", "title": "bad"},
        ]},
    }  # fmt: skip
    calls = mock_http(lambda r: httpx.Response(200, json=body))
    adapter = BraveSearchAdapter()
    raws = await adapter.run("Yan Liang Chan", ["singapore"])
    cands = adapter.parse(raws[0])
    assert [c.value for c in cands] == ["https://example.org/team"]  # non-http URLs dropped
    assert cands[0].type == "web_mention" and cands[0].source_reliability == "D"
    assert calls[0].headers["x-subscription-token"] == "k-123"
    assert "k-123" not in str(calls[0].url)  # never in the URL / logs
    assert parse_qs(urlparse(str(calls[0].url)).query)["q"] == ['"Yan Liang Chan" singapore']


async def test_brave_non_search_json_is_a_mismatch(mock_http, monkeypatch):
    monkeypatch.setattr(get_settings(), "brave_api_key", "k")
    mock_http(lambda r: httpx.Response(200, json={"type": "ErrorResponse", "error": {"code": "RATE_LIMITED"}}))
    with pytest.raises(SignatureMismatch):
        await BraveSearchAdapter().run("x", [])


# --- DuckDuckGo -----------------------------------------------------------------------


async def test_duckduckgo_accepts_its_javascript_content_type(mock_http):
    answer = {
        "Heading": "OWASP", "AbstractURL": "https://en.wikipedia.org/wiki/OWASP", "AbstractText": "Open Web...",
        "RelatedTopics": [
            {"FirstURL": "https://duckduckgo.com/OWASP_ZAP", "Text": "OWASP ZAP - a scanner"},
            {"Name": "See also", "Topics": [{"FirstURL": "https://duckduckgo.com/Amass", "Text": "Amass"}]},
        ],
    }  # fmt: skip
    mock_http(
        lambda r: httpx.Response(
            200, content=json.dumps(answer).encode(), headers={"content-type": "application/x-javascript"}
        )
    )
    adapter = DuckDuckGoAdapter()
    cands = adapter.parse((await adapter.run("OWASP", ["ignored-tag"]))[0])
    assert [c.value for c in cands] == [
        "https://en.wikipedia.org/wiki/OWASP",
        "https://duckduckgo.com/OWASP_ZAP",
        "https://duckduckgo.com/Amass",
    ]
    assert cands[0].source_reliability == "C" and cands[1].source_reliability == "D"
    assert adapter.check_health_output(cands).ok


async def test_duckduckgo_bot_page_is_a_mismatch(mock_http):
    mock_http(
        lambda r: httpx.Response(200, text="<html>anomaly detected</html>", headers={"content-type": "text/html"})
    )
    with pytest.raises(SignatureMismatch, match="isn't JSON"):
        await DuckDuckGoAdapter().run("x", [])


async def test_duckduckgo_empty_answer_is_a_valid_negative(mock_http):
    empty = {"Heading": "", "AbstractURL": "", "RelatedTopics": []}
    mock_http(lambda r: httpx.Response(200, json=empty))
    adapter = DuckDuckGoAdapter()
    assert adapter.parse((await adapter.run("nobody-anywhere-123", []))[0]) == []


# --- Search links -----------------------------------------------------------------------


def test_search_links_are_prefilled_with_value_and_tags():
    links = search_links("name", "Yan Liang Chan", ["singapore", "fintech", "third"])
    labels = [link.label for link in links]
    assert labels == [
        "Google", "Google Images", "Bing", "DuckDuckGo", "site:linkedin.com", "site:reddit.com", "site:pastebin.com",
    ]  # fmt: skip
    google = parse_qs(urlparse(links[0].url).query)["q"][0]
    assert google == '"Yan Liang Chan" singapore fintech'
    linkedin = parse_qs(urlparse(links[4].url).query)["q"][0]
    assert linkedin == 'site:linkedin.com "Yan Liang Chan" singapore fintech'


def test_image_targets_get_reverse_image_search():
    links = search_links("image", "https://example.org/p.jpg")
    assert {link.group for link in links} == {"Reverse image"}
    assert {link.label for link in links} == {"Google Lens", "Yandex Images", "Bing Visual Search", "TinEye"}
    assert all("example.org%2Fp.jpg" in link.url for link in links)


def test_urls_are_searched_as_plain_text_and_empty_values_get_nothing():
    links = search_links("account", "https://github.com/x", [])
    assert parse_qs(urlparse(links[0].url).query)["q"][0] == "https://github.com/x"
    assert search_links("name", "  ", []) == []


async def test_entity_rows_carry_the_search_menu(client, db):
    import uuid

    from app import jobs
    from tests.conftest import case_form_data, login

    csrf = await login(client)
    r = await client.post(
        "/cases", data=case_form_data(csrf, name=f"S {uuid.uuid4().hex[:6]}", tools=["fake_ok"], target_tags="osint")
    )
    await jobs.wait_for_all()
    case_id = r.headers["location"].rsplit("/", 1)[1]
    table = await client.get(f"/cases/{case_id}/entities")
    assert "Search ↗" in table.text
    assert "%22janedoe%22+osint" in table.text  # value + context tag, URL-encoded
    assert 'rel="noopener noreferrer nofollow"' in table.text
