"""Web search adapters: Brave Search API and DuckDuckGo Instant Answers.

Search hits are *mentions*, not identity evidence: they get low reliability
and a low prior, and mostly earn their place through context-tag matches and
corroboration during correlation.
"""

from __future__ import annotations

from urllib.parse import urlparse

from app.adapters import http
from app.adapters.base import (
    EntityCandidate,
    HealthResult,
    InvalidTarget,
    RawResult,
    SignatureMismatch,
    ToolAdapter,
)
from app.config import get_settings

SEARCHABLE = ["username", "email", "name", "domain", "phone"]
MAX_QUERY_TAGS = 2


def build_query(value: str, context_tags: list[str]) -> str:
    """Exact-phrase search for the value, narrowed by up to two context tags."""
    value = value.strip().replace('"', "")
    if not value or len(value) > 200:
        raise InvalidTarget("search value must be 1–200 characters")
    tags = [t.replace('"', "").strip() for t in context_tags if t.strip()][:MAX_QUERY_TAGS]
    return " ".join([f'"{value}"', *tags])


def _mention(url: str, title: str, snippet: str, query: str, source: str, reliability: str) -> EntityCandidate:
    return EntityCandidate(
        type="web_mention",
        value=url,
        attributes={
            "url": url,
            "host": urlparse(url).hostname,
            "title": title[:300],
            "snippet": snippet[:600],
            "query": query,
        },
        source_reliability=reliability,
        confidence=0.25,
        field_confidence={"mentions_value": 0.6, "same_person": 0.25},
        relation_type="mentioned_on",
        relation_explanation=f"{source} result for the exact value",
    )


class BraveSearchAdapter(ToolAdapter):
    name = "brave"
    label = "Brave Search"
    input_types = SEARCHABLE
    description = "Web search via the Brave Search API (needs UNMASK_BRAVE_API_KEY)."
    health_check_target = "OWASP Amass"
    timeout_seconds = 60
    endpoint = "https://api.search.brave.com/res/v1/web/search"

    def configured(self) -> str | None:
        return None if get_settings().brave_api_key else "No API key configured (UNMASK_BRAVE_API_KEY)"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        query = build_query(target_value, context_tags)
        s = get_settings()
        results: list[dict] = []
        for offset in range(max(1, s.brave_max_results // 20)):
            _, data = await http.get_json(
                self.endpoint,
                params={"q": query, "count": 20, "offset": offset, "safesearch": "off"},
                headers={"X-Subscription-Token": s.brave_api_key},
                timeout=self.timeout_seconds,
            )
            if not isinstance(data, dict) or data.get("type") != "search":
                raise SignatureMismatch("Brave returned JSON that is not a search response")
            page = ((data.get("web") or {}).get("results")) or []
            results.extend(page)
            if not (data.get("query") or {}).get("more_results_available") or len(page) < 20:
                break
        return [RawResult(self.name, target_value, {"query": query, "results": results})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        q = raw.payload["query"]
        return [
            _mention(r["url"], r.get("title", ""), r.get("description", ""), q, "Brave Search", "D")
            for r in raw.payload["results"]
            if isinstance(r, dict) and str(r.get("url", "")).startswith(("http://", "https://"))
        ]


class DuckDuckGoAdapter(ToolAdapter):
    name = "duckduckgo"
    label = "DuckDuckGo"
    input_types = SEARCHABLE
    description = (
        "DuckDuckGo Instant Answers (official API): reference summaries and related topics, not full web results."
    )
    health_check_target = "OWASP"
    timeout_seconds = 60
    endpoint = "https://api.duckduckgo.com/"

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        # Instant Answers work on the bare subject; tags would only defeat the match.
        query = build_query(target_value, []).strip('"')
        _, data = await http.get_json(
            self.endpoint,
            params={"q": query, "format": "json", "no_html": 1, "skip_disambig": 1, "no_redirect": 1},
            timeout=self.timeout_seconds,
            strict_content_type=False,
        )
        if not isinstance(data, dict) or not {"Heading", "RelatedTopics", "AbstractURL"} <= data.keys():
            raise SignatureMismatch("DuckDuckGo returned JSON without the Instant Answer fields")
        return [RawResult(self.name, target_value, {"query": query, "answer": data})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        a, q = raw.payload["answer"], raw.payload["query"]
        out = []
        if a.get("AbstractURL"):
            out.append(
                _mention(a["AbstractURL"], a.get("Heading", ""), a.get("AbstractText", ""), q, "DuckDuckGo", "C")
            )

        def topics(items):
            for t in items or []:
                if "Topics" in t:  # grouped sub-topics
                    yield from topics(t["Topics"])
                elif t.get("FirstURL"):
                    yield t

        for t in topics(a.get("RelatedTopics")):
            out.append(_mention(t["FirstURL"], t.get("Text", "")[:120], t.get("Text", ""), q, "DuckDuckGo", "D"))
        return out

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        if candidates:
            return HealthResult(True, f"{len(candidates)} results for a well-known topic")
        return HealthResult(False, "no Instant Answer for a well-known topic")
