import json
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from app.adapters import http
from app.adapters.base import AdapterError, InvalidTarget, SignatureMismatch
from app.adapters.websearch import DuckDuckGoAdapter, WebSearchAdapter, build_query, guess_type, normalize_url
from app.config import get_settings
from app.search.providers import BraveProvider, SerperProvider, active_provider
from app.search.queries import build_queries
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


# --- Search providers and the web search adapter ----------------------------------------


@pytest.fixture
def no_search_keys(monkeypatch):
    s = get_settings()
    for key in ("serper_key", "serpapi_key", "google_api_key", "google_cx", "brave_api_key", "search_provider"):
        monkeypatch.setattr(s, key, "")
    return s


def test_web_search_is_not_configured_without_a_key(no_search_keys):
    reason = WebSearchAdapter().configured()
    assert "Integrations page" in reason and "Serper" in reason and "Brave" in reason


def test_provider_order_and_explicit_choice(no_search_keys, monkeypatch):
    monkeypatch.setattr(no_search_keys, "brave_api_key", "b")
    monkeypatch.setattr(no_search_keys, "serpapi_key", "s")
    assert active_provider().name == "serpapi"
    monkeypatch.setattr(no_search_keys, "search_provider", "brave")
    assert active_provider().name == "brave"


async def test_brave_provider_sends_the_key_as_a_header_and_drops_bad_urls(mock_http, no_search_keys, monkeypatch):
    monkeypatch.setattr(no_search_keys, "brave_api_key", "k-123")
    body = {"type": "search", "web": {"results": [
        {"url": "https://example.org/team", "title": "Team", "description": "Jane Doe, Lisbon"},
        {"url": "javascript:alert(1)", "title": "bad"},
    ]}}  # fmt: skip
    calls = mock_http(lambda r: httpx.Response(200, json=body))
    hits = await BraveProvider().search('"Jane Doe"', 10)
    assert [h.url for h in hits] == ["https://example.org/team"]
    assert calls[0].headers["x-subscription-token"] == "k-123"
    assert "k-123" not in str(calls[0].url)  # never in the URL / logs


async def test_serper_provider_posts_the_query(mock_http, no_search_keys, monkeypatch):
    monkeypatch.setattr(no_search_keys, "serper_key", "sk")
    body = {"searchParameters": {"q": "x"}, "organic": [{"link": "https://a.example/", "title": "A", "snippet": "s"}]}
    calls = mock_http(lambda r: httpx.Response(200, json=body))
    hits = await SerperProvider().search('"x"', 10)
    assert hits[0].url == "https://a.example/" and calls[0].method == "POST"
    assert json.loads(calls[0].content) == {"q": '"x"', "num": 10} and calls[0].headers["x-api-key"] == "sk"


async def test_provider_error_json_is_a_mismatch(mock_http, no_search_keys, monkeypatch):
    monkeypatch.setattr(no_search_keys, "brave_api_key", "k")
    mock_http(lambda r: httpx.Response(200, json={"type": "ErrorResponse", "error": {"code": "RATE_LIMITED"}}))
    with pytest.raises(SignatureMismatch):
        await BraveProvider().search("x", 10)


def test_username_queries_cover_context_social_developer_and_documents():
    queries = build_queries("username", "janedoe", ["lisbon", "logistics", "ignored"])
    labels = [q.label for q in queries]
    assert labels[:3] == ["Exact match", "With context: lisbon", "With context: logistics"]
    assert {"Social networks", "Developer sites and forums", "Username in a web address", "Documents"} <= set(labels)
    assert queries[0].text == '"janedoe"' and "site:linkedin.com" in queries[3].text


def test_name_and_domain_queries():
    name = [q.text for q in build_queries("name", 'Jane "Doe"', ["lisbon", "acme"])]
    assert name[1] == '"Jane Doe" "lisbon" "acme"' and '"Jane Doe" site:linkedin.com/in' in name
    domain = [q.text for q in build_queries("domain", "acme.example", [])]
    assert domain[:3] == ["site:acme.example", '"acme.example" -site:acme.example', '"@acme.example"']
    assert len(build_queries("username", "janedoe", ["a", "b"], limit=3)) == 3


def test_guess_type_and_url_normalisation():
    assert [guess_type(v) for v in ("a@b.example", "+65 9123 4567", "acme.example", "Jane Doe", "janedoe")] == [
        "email", "phone", "domain", "name", "username"
    ]  # fmt: skip
    assert normalize_url("https://Ex.com/a/?utm_source=x&id=2#top") == "https://ex.com/a?id=2"


async def test_web_search_merges_queries_and_extracts_profiles_and_emails(mock_http, no_search_keys, monkeypatch):
    monkeypatch.setattr(no_search_keys, "serper_key", "sk")

    def handler(request):
        q = json.loads(request.content)["q"]
        organic = [{"link": "https://blog.example/team?utm_source=x", "title": "Team",
                    "snippet": "Jane Doe (jane.doe@acme.example), Lisbon"}]  # fmt: skip
        if "site:linkedin.com" in q:
            organic.append({"link": "https://www.linkedin.com/in/janedoe/", "title": "Jane Doe", "snippet": "Lisbon"})
        if "Documents" not in q and "filetype" in q:
            return httpx.Response(500)
        return httpx.Response(200, json={"searchParameters": {"q": q}, "organic": organic})

    mock_http(handler)
    adapter = WebSearchAdapter()
    raw = (await adapter.run("janedoe", ["lisbon"]))[0]
    assert raw.payload["provider"] == "Google (Serper)"
    assert raw.payload["failed"] == [("Documents", "HTTP 500 from google.serper.dev")]
    cands = adapter.parse(raw)
    mentions = [c for c in cands if c.type == "web_mention"]
    team = next(c for c in mentions if "blog.example" in c.value)
    assert len(team.attributes["found_by"]) >= 5 and team.confidence == 0.4  # many queries, one entity
    account = next(c for c in cands if c.type == "account")
    assert account.attributes["site"] == "LinkedIn" and account.value == "https://www.linkedin.com/in/janedoe"
    assert [c.value for c in cands if c.type == "email"] == ["jane.doe@acme.example"]


async def test_web_search_fails_loudly_when_every_query_fails(mock_http, no_search_keys, monkeypatch):
    monkeypatch.setattr(no_search_keys, "serper_key", "sk")
    mock_http(lambda r: httpx.Response(403))
    with pytest.raises(AdapterError, match="all 5 searches failed"):
        await WebSearchAdapter().run("janedoe", [])


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
    assert "Search the web" in table.text
    assert "%22janedoe%22+osint" in table.text  # value + context tag, URL-encoded
    assert 'rel="noopener noreferrer nofollow"' in table.text
