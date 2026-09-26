"""Pre-built search links for manual follow-up (opened by the analyst, not the platform).

Each link opens in a new tab with no referrer. The engine still sees the query,
which the UI says next to the links.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote_plus

SITE_FILTERS = ["linkedin.com", "reddit.com", "pastebin.com"]
# Values worth quoting as an exact phrase.
_PHRASE_TYPES = {"username", "email", "name", "phone", "domain", "hostname", "registration"}
IMAGE_TYPES = {"image"}


@dataclass(frozen=True)
class SearchLink:
    group: str
    label: str
    url: str


def _q(value: str, tags: list[str]) -> str:
    return " ".join([f'"{value}"', *[t for t in tags[:2] if t]])


def search_links(entity_type: str, value: str, tags: list[str] | None = None) -> list[SearchLink]:
    tags = [t.strip() for t in (tags or []) if t and t.strip()]
    value = value.strip().replace('"', "")
    if not value:
        return []
    if entity_type in IMAGE_TYPES:
        enc = quote_plus(value)
        return [
            SearchLink("Reverse image", "Google Lens", f"https://lens.google.com/uploadbyurl?url={enc}"),
            SearchLink("Reverse image", "Yandex Images", f"https://yandex.com/images/search?rpt=imageview&url={enc}"),
            SearchLink("Reverse image", "Bing Visual Search", f"https://www.bing.com/images/search?view=detailv2&iss=sbi&q=imgurl:{enc}"),
            SearchLink("Reverse image", "TinEye", f"https://tineye.com/search?url={enc}"),
        ]  # fmt: skip

    phrase = _q(value, tags) if entity_type in _PHRASE_TYPES else value
    enc = quote_plus(phrase)
    links = [
        SearchLink("Search", "Google", f"https://www.google.com/search?q={enc}"),
        SearchLink("Search", "Google Images", f"https://www.google.com/search?tbm=isch&q={enc}"),
        SearchLink("Search", "Bing", f"https://www.bing.com/search?q={enc}"),
        SearchLink("Search", "DuckDuckGo", f"https://duckduckgo.com/?q={enc}"),
    ]
    for site in SITE_FILTERS:
        links.append(
            SearchLink(
                "Site", f"site:{site}", f"https://www.google.com/search?q={quote_plus(f'site:{site} ' + phrase)}"
            )
        )
    return links
