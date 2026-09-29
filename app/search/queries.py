"""Targeted search queries per target type.

One exact-phrase search is what an analyst would type by hand. The value of
running searches here is breadth with precision: the same identifier asked
several focused questions (on social networks, on developer sites, next to
each context tag, inside documents), all run at once, merged and remembered.
Every query carries a plain label, so a result says why it was found.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.adapters.base import InvalidTarget

SOCIAL = ["linkedin.com", "x.com", "twitter.com", "instagram.com", "facebook.com", "tiktok.com"]
DEV_AND_FORUMS = ["github.com", "gitlab.com", "stackoverflow.com", "reddit.com", "medium.com", "dev.to"]
PASTES_AND_CODE = ["pastebin.com", "github.com", "gitlab.com", "gist.github.com"]
DOCUMENTS = "(filetype:pdf OR filetype:doc OR filetype:docx)"
MAX_TAGS = 2
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9._\-]+$")


@dataclass(frozen=True)
class Query:
    text: str
    label: str


def _clean(value: str) -> str:
    value = re.sub(r"\s+", " ", value.replace('"', "")).strip()
    if not value or len(value) > 200:
        raise InvalidTarget("search value must be 1–200 characters")
    return value


def _sites(sites: list[str]) -> str:
    return "(" + " OR ".join(f"site:{s}" for s in sites) + ")"


def build_queries(target_type: str, value: str, context_tags: list[str], limit: int = 8) -> list[Query]:
    v = _clean(value)
    tags = [_clean(t) for t in context_tags if t.strip()][:MAX_TAGS]
    exact = f'"{v}"'
    queries = [Query(exact, "Exact match")]
    queries += [Query(f'{exact} "{t}"', f"With context: {t}") for t in tags]

    if target_type == "username":
        queries += [
            Query(f"{exact} {_sites(SOCIAL)}", "Social networks"),
            Query(f"{exact} {_sites(DEV_AND_FORUMS)}", "Developer sites and forums"),
        ]
        if _SAFE_TOKEN.match(v):
            queries.append(Query(f"inurl:{v}", "Username in a web address"))
        queries.append(Query(f"{exact} {DOCUMENTS}", "Documents"))
    elif target_type == "name":
        queries += [
            Query(f"{exact} site:linkedin.com/in", "LinkedIn profiles"),
            Query(f"{exact} {_sites(SOCIAL[1:])}", "Social networks"),
            Query(f'{exact} (resume OR cv OR "about me" OR portfolio)', "About pages and CVs"),
            Query(f"{exact} {DOCUMENTS}", "Documents"),
        ]
        if len(tags) == MAX_TAGS:
            queries.insert(1, Query(f'{exact} "{tags[0]}" "{tags[1]}"', "With all context"))
    elif target_type == "email":
        handle = v.split("@", 1)[0]
        if len(handle) >= 5 and _SAFE_TOKEN.match(handle):
            queries.append(Query(f'"{handle}" -"{v}"', "Address handle used elsewhere"))
        queries += [
            Query(f"{exact} {_sites(PASTES_AND_CODE)}", "Code and paste sites"),
            Query(f"{exact} {DOCUMENTS}", "Documents"),
        ]
    elif target_type == "domain":
        queries = [
            Query(f"site:{v}", "Pages on the domain"),
            Query(f"{exact} -site:{v}", "Mentions elsewhere"),
            Query(f'"@{v}"', "Email addresses at the domain"),
            *[Query(f'{exact} "{t}"', f"With context: {t}") for t in tags],
        ]
    elif target_type == "phone":
        digits = re.sub(r"\D", "", v)
        if digits and digits != v:
            queries.append(Query(f'"{digits}"', "Digits only"))

    seen, out = set(), []
    for q in queries:
        if q.text not in seen:
            seen.add(q.text)
            out.append(q)
    return out[:limit]
