"""Search engine APIs behind one interface.

Each provider turns a query into ranked hits (url, title, snippet). Only
official APIs are used, never scraped result pages, so a provider either
answers properly or fails loudly: a JSON error, a quota message or a
bot-check page is an error, never "no results".

Choose one with ``UNMASK_SEARCH_PROVIDER``; by default the first provider with
a key configured is used, in the order below.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import ClassVar

from app.adapters import http
from app.adapters.base import SignatureMismatch
from app.config import get_settings


@dataclass
class SearchHit:
    url: str
    title: str
    snippet: str
    rank: int


def _hits(items: list, url_key: str, title_key: str, snippet_key: str) -> list[SearchHit]:
    out = []
    for i, item in enumerate(items or []):
        if not isinstance(item, dict):
            continue
        url = str(item.get(url_key) or "")
        if url.startswith(("http://", "https://")):
            out.append(
                SearchHit(url, str(item.get(title_key) or "")[:300], str(item.get(snippet_key) or "")[:600], i + 1)
            )
    return out


class SearchProvider(ABC):
    name: ClassVar[str]
    label: ClassVar[str]
    key_hint: ClassVar[str]

    @abstractmethod
    def configured(self) -> bool: ...

    @abstractmethod
    async def search(self, query: str, count: int) -> list[SearchHit]: ...


class SerperProvider(SearchProvider):
    """Google results via serper.dev."""

    name, label, key_hint = "serper", "Google (Serper)", "UNMASK_SERPER_KEY"
    endpoint = "https://google.serper.dev/search"

    def configured(self) -> bool:
        return bool(get_settings().serper_key)

    async def search(self, query: str, count: int) -> list[SearchHit]:
        _, data = await http.post_json(
            self.endpoint, body={"q": query, "num": count}, headers={"X-API-KEY": get_settings().serper_key}
        )
        if not isinstance(data, dict) or "searchParameters" not in data:
            raise SignatureMismatch("Serper returned JSON that is not a search response")
        return _hits(data.get("organic"), "link", "title", "snippet")


class SerpApiProvider(SearchProvider):
    """Google results via serpapi.com."""

    name, label, key_hint = "serpapi", "Google (SerpAPI)", "UNMASK_SERPAPI_KEY"
    endpoint = "https://serpapi.com/search.json"

    def configured(self) -> bool:
        return bool(get_settings().serpapi_key)

    async def search(self, query: str, count: int) -> list[SearchHit]:
        _, data = await http.get_json(
            self.endpoint, params={"engine": "google", "q": query, "num": count, "api_key": get_settings().serpapi_key}
        )
        if not isinstance(data, dict) or "search_metadata" not in data:
            raise SignatureMismatch("SerpAPI returned JSON that is not a search response")
        if data.get("error") and "hasn't returned any results" not in str(data["error"]):
            raise SignatureMismatch(f"SerpAPI error: {str(data['error'])[:200]}")
        return _hits(data.get("organic_results"), "link", "title", "snippet")


class GoogleCseProvider(SearchProvider):
    """Google Programmable Search Engine (Custom Search JSON API)."""

    name, label, key_hint = "google", "Google Programmable Search", "UNMASK_GOOGLE_API_KEY and UNMASK_GOOGLE_CX"
    endpoint = "https://www.googleapis.com/customsearch/v1"

    def configured(self) -> bool:
        s = get_settings()
        return bool(s.google_api_key and s.google_cx)

    async def search(self, query: str, count: int) -> list[SearchHit]:
        s = get_settings()
        _, data = await http.get_json(
            self.endpoint, params={"key": s.google_api_key, "cx": s.google_cx, "q": query, "num": min(count, 10)}
        )
        if not isinstance(data, dict) or data.get("kind") != "customsearch#search":
            raise SignatureMismatch("Google returned JSON that is not a search response")
        return _hits(data.get("items"), "link", "title", "snippet")


class BraveProvider(SearchProvider):
    name, label, key_hint = "brave", "Brave Search", "UNMASK_BRAVE_API_KEY"
    endpoint = "https://api.search.brave.com/res/v1/web/search"

    def configured(self) -> bool:
        return bool(get_settings().brave_api_key)

    async def search(self, query: str, count: int) -> list[SearchHit]:
        _, data = await http.get_json(
            self.endpoint,
            params={"q": query, "count": min(count, 20), "safesearch": "off"},
            headers={"X-Subscription-Token": get_settings().brave_api_key},
        )
        if not isinstance(data, dict) or data.get("type") != "search":
            raise SignatureMismatch("Brave returned JSON that is not a search response")
        return _hits((data.get("web") or {}).get("results"), "url", "title", "description")


PROVIDERS: tuple[SearchProvider, ...] = (SerperProvider(), SerpApiProvider(), GoogleCseProvider(), BraveProvider())


def active_provider() -> SearchProvider | None:
    wanted = get_settings().search_provider.strip().lower()
    for p in PROVIDERS:
        if (not wanted or p.name == wanted) and p.configured():
            return p
    return None


def setup_hint() -> str:
    return "No search API key configured. Set one of: " + "; ".join(f"{p.key_hint} ({p.label})" for p in PROVIDERS)
