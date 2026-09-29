"""Web search adapters: targeted searches through a search API, and DuckDuckGo Instant Answers.

Search hits are *mentions*, not identity evidence: they get low reliability
and a low prior, and mostly earn their place through context-tag matches and
corroboration during correlation.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlparse

from app.adapters import http
from app.adapters.base import (
    AdapterError,
    EntityCandidate,
    HealthResult,
    InvalidTarget,
    RawResult,
    SignatureMismatch,
    ToolAdapter,
)
from app.config import get_settings
from app.identifiers import guess_type
from app.search.profiles import match_profile
from app.search.providers import active_provider, setup_hint
from app.search.queries import Query, build_queries

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


_EMAIL_IN_TEXT = re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,24}\b")
_TRACKING = re.compile(r"^(?:utm_|fbclid|gclid|ref$|ref_src$)")
QUERY_CONCURRENCY = 4


def normalize_url(url: str) -> str:
    """One key per page: lowercase host, no fragment, no tracking parameters, no trailing slash."""
    p = urlparse(url)
    query = "&".join(kv for kv in p.query.split("&") if kv and not _TRACKING.match(kv.split("=", 1)[0]))
    path = p.path.rstrip("/") or "/"
    return f"{p.scheme}://{(p.hostname or '').lower()}{path}{'?' + query if query else ''}"


class WebSearchAdapter(ToolAdapter):
    """Runs a set of targeted queries through one search API and merges the results."""

    name = "websearch"
    label = "Web search"
    input_types = SEARCHABLE
    description = (
        "Several targeted web searches per target (exact match, with context, social and developer sites, "
        "documents), merged. Needs a search API key."
    )
    health_check_target = "OWASP Amass"
    timeout_seconds = 180
    verify_accounts = True

    def configured(self) -> str | None:
        return None if active_provider() else setup_hint()

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        provider = active_provider()
        if provider is None:
            raise AdapterError(setup_hint())
        s = get_settings()
        queries = build_queries(guess_type(target_value), target_value, context_tags, s.search_max_queries)
        sem = asyncio.Semaphore(QUERY_CONCURRENCY)

        async def one(q: Query):
            async with sem:
                try:
                    return q, await provider.search(q.text, s.search_results_per_query), None
                except AdapterError as exc:
                    return q, [], str(exc) or exc.__class__.__name__

        outcomes = await asyncio.gather(*(one(q) for q in queries))
        failed = [(q.label, err) for q, _, err in outcomes if err]
        if len(failed) == len(queries):
            raise AdapterError(f"all {len(queries)} searches failed: {failed[0][1]}")
        hits: dict[str, dict] = {}
        for q, results, _ in outcomes:
            for h in results:
                key = normalize_url(h.url)
                entry = hits.setdefault(key, {"url": h.url, "title": h.title, "snippet": h.snippet, "rank": h.rank,
                                              "found_by": []})  # fmt: skip
                entry["rank"] = min(entry["rank"], h.rank)
                if q.label not in entry["found_by"]:
                    entry["found_by"].append(q.label)
                if len(h.snippet) > len(entry["snippet"]):
                    entry["snippet"] = h.snippet
        payload = {
            "provider": provider.label,
            "queries": [{"text": q.text, "label": q.label, "results": len(r)} for q, r, _ in outcomes],
            "failed": failed,
            "hits": list(hits.values()),
        }
        return [RawResult(self.name, target_value, payload)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        payload = raw.payload
        target = raw.target_value.strip().casefold()
        out: list[EntityCandidate] = []
        emails: set[str] = set()
        for hit in payload["hits"]:
            found_by = hit["found_by"]
            # A page several different queries lead to is a little more likely to be about the subject.
            prior = min(0.4, 0.25 + 0.05 * (len(found_by) - 1))
            mention = _mention(hit["url"], hit["title"], hit["snippet"], found_by[0], payload["provider"], "D")
            mention.confidence = prior
            mention.attributes.update({"found_by": found_by, "provider": payload["provider"], "rank": hit["rank"]})
            mention.relation_explanation = f"{payload['provider']} result ({', '.join(found_by)})"
            out.append(mention)

            profile = match_profile(hit["url"])
            if profile:
                out.append(
                    EntityCandidate(
                        type="account",
                        value=profile.url,
                        attributes={
                            "site": profile.site,
                            "username": profile.handle,
                            "url": profile.url,
                            "host": urlparse(profile.url).hostname,
                            "origin": "web search",
                            "found_by": found_by,
                        },  # fmt: skip
                        source_reliability="C",
                        confidence=0.4,
                        field_confidence={"exists": 0.6, "same_person": 0.4},
                        relation_type="has_account",
                        relation_explanation=f"profile found by web search ({', '.join(found_by)})",
                    )
                )
            for email in _EMAIL_IN_TEXT.findall(f"{hit['title']} {hit['snippet']}"):
                email = email.lower().strip(".")
                if email != target and email not in emails:
                    emails.add(email)
                    out.append(
                        EntityCandidate(
                            type="email",
                            value=email,
                            attributes={"origin": "search result snippet", "url": hit["url"]},
                            source_reliability="D",
                            confidence=0.3,
                            field_confidence={"same_person": 0.3},
                            relation_type="mentioned_with",
                            relation_explanation=f"address appears in a search result for the target ({hit['url']})",
                        )
                    )
        return out

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        hosts = {c.attributes.get("host") or "" for c in candidates if c.type == "web_mention"}
        if any("owasp" in h or "github" in h for h in hosts):
            return HealthResult(True, f"{len(candidates)} results for a well-known project")
        return HealthResult(False, "search for a well-known project returned nothing recognisable")


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
