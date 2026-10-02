"""Evidence for and against a finding, in plain words.

The score says how likely a finding is; this says *why*, as short lines an
analyst can check at a glance: the page names the same username, the display
name matches the subject's, the profile links to an account already confirmed,
the username is a common word. Every line is built from data already stored
(the page check, the targets, relations, which tools saw it); nothing here
fetches anything.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from urllib.parse import urlparse

from rapidfuzz import fuzz

from app.correlation import normalize as norm
from app.models import Entity, Relation, Target

CORROBORATING = {"shares_handle", "profile_name_match", "email_at_domain", "breach_associated", "profile_links_to"}
NAME_MATCH = 85
WEAK_RARITY = 0.5


@dataclass
class Signal:
    label: str
    detail: str = ""


@dataclass
class LinkChip:
    url: str
    label: str
    entity_id: object | None = None
    state: str = ""  # "target" | "confirmed" | "found" | ""


@dataclass
class ProfileView:
    name: str = ""
    handle: str = ""
    site: str = ""
    location: str = ""
    about: str = ""
    excerpt: str = ""


@dataclass
class Evidence:
    for_: list[Signal] = field(default_factory=list)
    against: list[Signal] = field(default_factory=list)
    notes: list[Signal] = field(default_factory=list)
    terms: list[str] = field(default_factory=list)
    links: list[LinkChip] = field(default_factory=list)
    profile: ProfileView = field(default_factory=ProfileView)

    @property
    def summary(self) -> str:
        parts = []
        if self.for_:
            parts.append(f"{len(self.for_)} for")
        if self.against:
            parts.append(f"{len(self.against)} against")
        return " · ".join(parts) or "No evidence either way"


@dataclass
class CaseIndex:
    """What else the case knows, keyed by canonical value: lets links point at findings."""

    by_value: dict[str, Entity] = field(default_factory=dict)

    @classmethod
    def build(cls, entities: Iterable[Entity]) -> CaseIndex:
        idx = cls()
        for e in entities:
            if e.dismissed_flag or e.merged_into_id is not None:
                continue
            key = _key(e.type, e.value)
            if key and (key not in idx.by_value or e.is_seed or e.confirmed_flag):
                idx.by_value[key] = e
        return idx

    def find(self, value: str, kind: str) -> Entity | None:
        return self.by_value.get(_key(kind, value) or "")


def _key(kind: str, value: str) -> str | None:
    if kind == "email":
        return "email:" + norm.canonical_email(value)
    if kind in ("account", "url", "web_mention"):
        u = urlparse(value if "://" in value else "https://" + value)
        host = (u.hostname or "").removeprefix("www.")
        return "url:" + host + u.path.rstrip("/").lower() if host else None
    if kind == "domain":
        return "url:" + value.lower().removeprefix("www.").rstrip("/")
    return None


def _handle(entity: Entity) -> str:
    a = entity.attributes or {}
    preview = a.get("preview") or {}
    handle = a.get("username") or preview.get("username") or ""
    if not handle and entity.type == "account":
        from app.search.profiles import match_profile

        p = match_profile(entity.value)
        handle = p.handle if p else ""
    return str(handle)


def _display_name(entity: Entity, handle: str) -> str:
    a = entity.attributes or {}
    profile = a.get("profile") or {}
    name = profile.get("fullname") or profile.get("name") or a.get("name") or ""
    if not name and (title := (a.get("preview") or {}).get("title")):
        from app.correlation.engine import _title_name

        name = _title_name(title, handle) or ""
    return str(name)


def _when(iso: str | None) -> str:
    from datetime import datetime

    try:
        return "checked " + datetime.fromisoformat(iso).strftime("%-d %b %Y") if iso else ""
    except ValueError:
        return ""


def evidence(
    entity: Entity,
    *,
    targets: Iterable[Target],
    relations: Iterable[tuple[Relation, Entity]] = (),
    tools: Iterable[str] = (),
    index: CaseIndex | None = None,
) -> Evidence:
    """The for/against lines for one finding. ``relations`` pairs each relation with the entity at its other end."""
    from app.correlation.commonness import username_rarity
    from app.search.profiles import handle_relates_to
    from app.verify import is_site_account

    ev = Evidence()
    a = entity.attributes or {}
    preview = a.get("preview") or {}
    profile = a.get("profile") or {}
    targets = list(targets)
    usernames = [t.value for t in targets if t.type == "username"]
    usernames += [norm.email_handle(t.value) for t in targets if t.type == "email"]
    names = [t.value for t in targets if t.type == "name"]
    tags = [tag for t in targets for tag in (t.context_tags or []) if tag.strip()]

    handle = _handle(entity)
    name = _display_name(entity, handle)
    host = (urlparse(entity.value).hostname or "") if entity.type == "account" else ""
    ev.profile = ProfileView(
        name=name,
        handle=handle,
        site=a.get("site") or host.removeprefix("www."),
        location=str(profile.get("location") or profile.get("city") or a.get("location") or ""),
        about=str(profile.get("bio") or preview.get("description") or ""),
        excerpt=str(preview.get("excerpt") or ""),
    )
    ev.terms = [*usernames, *names, *(p for n in names for p in n.split() if len(p) >= 3)]

    if entity.is_seed:
        ev.notes.append(Signal("This is one of the identifiers you searched for"))
        return ev

    # --- The page check ------------------------------------------------------------------------
    if entity.type == "account":
        checked = _when(preview.get("checked_at"))
        reason = a.get("verification_reason") or ""
        if entity.verification == "verified":
            detail = reason[:1].upper() + reason[1:] if reason else "The page names the username"
            ev.for_.append(Signal("Profile page checked", f"{detail}{f' · {checked}' if checked else ''}"))
        elif entity.verification == "unverified":
            ev.against.append(Signal("Profile page couldn't be confirmed", reason[:1].upper() + reason[1:]))
        else:
            ev.notes.append(Signal("Profile page not checked"))

    # --- Username ------------------------------------------------------------------------------
    if handle and usernames:
        exact = next((u for u in usernames if norm.handle(u) == norm.handle(handle)), None)
        close = exact or next((u for u in usernames if handle_relates_to(handle, u)), None)
        if exact:
            ev.for_.append(Signal("Same username as the subject", f"'{handle}'"))
        elif close:
            ev.for_.append(Signal("Username resembles the subject's", f"'{handle}' vs '{close}'"))
        elif not a.get("linked_from"):
            ev.against.append(Signal("Different username", f"'{handle}' vs '{usernames[0]}'"))
    if handle and entity.type == "account" and not a.get("linked_from") and usernames:
        rarity, why = username_rarity(handle)
        if rarity < WEAK_RARITY and why:
            ev.against.append(Signal("Common username: a match means little", why[:1].upper() + why[1:]))
    if handle and host and is_site_account(handle, host):
        ev.against.append(
            Signal("Looks like the site's own account", f"'{handle}' carries the {ev.profile.site} brand")
        )

    # --- Display name --------------------------------------------------------------------------
    if name and names:
        best, score = max(((n, fuzz.token_sort_ratio(norm.canonical_name(name), norm.canonical_name(n)))
                           for n in names), key=lambda x: x[1])  # fmt: skip
        if score >= NAME_MATCH:
            ev.for_.append(Signal("Display name matches the subject", f"'{name}' ≈ '{best}' ({score:.0f}%)"))
        elif norm.initials_compatible(name, best) and score >= 60:
            ev.notes.append(Signal("Display name is similar", f"'{name}' vs '{best}' ({score:.0f}%)"))
        else:
            ev.against.append(Signal("The page names someone else", f"'{name}', not '{best}'"))

    # --- Context tags --------------------------------------------------------------------------
    haystack = " ".join(str(x) for x in (name, ev.profile.about, ev.profile.location, ev.profile.excerpt,
                                          preview.get("title", ""))).casefold()  # fmt: skip
    if tags and haystack.strip():
        found = [t for t in dict.fromkeys(tags)
                 if t.casefold() in haystack or fuzz.partial_ratio(t.casefold(), haystack) >= 90]  # fmt: skip
        if found:
            ev.for_.append(Signal("Mentions the case context", ", ".join(found)))
            ev.terms.extend(found)
        elif entity.type == "account" and entity.verification == "verified":
            ev.notes.append(Signal("None of the case tags appear on the page", ", ".join(dict.fromkeys(tags))))

    # --- Links on the page ---------------------------------------------------------------------
    if a.get("linked_from"):
        ev.for_.append(Signal("Linked from another profile", str(a.get("origin") or a["linked_from"])))
    for url in preview.get("links") or []:
        ev.links.append(_chip(url, "account", index))
    for email in preview.get("emails") or []:
        ev.links.append(_chip(email, "email", index, label=email))
    strong = [c for c in ev.links if c.state in ("target", "confirmed")]
    if strong:
        ev.for_.append(Signal("Links to what you already know", ", ".join(c.label for c in strong[:3])))
    ev.links.sort(key=lambda c: ("target", "confirmed", "found", "").index(c.state))

    # --- Relations and tools -------------------------------------------------------------------
    seen: set[str] = set()
    for rel, other in relations:
        why = rel.match_explanation or rel.relation_type.replace("_", " ")
        if rel.relation_type == "profile_name_match" and any(f.label.startswith("Display name") for f in ev.for_):
            continue  # already said, with the names side by side
        if rel.relation_type in CORROBORATING and why not in seen:
            seen.add(why)
            ev.for_.append(Signal("Corroborated", why[:1].upper() + why[1:]))
        elif rel.relation_type == "possible_same":
            ev.notes.append(Signal("May be the same as another finding", f"{other.value}: {why}"))
    tools = sorted({t for t in tools if t and t != "analyst"})
    if len(tools) >= 2:
        ev.for_.append(Signal(f"Found by {len(tools)} tools", ", ".join(tools)))

    ev.terms = [t for t in dict.fromkeys(x.strip() for x in ev.terms) if len(t) >= 3][:8]
    return ev


def _chip(value: str, kind: str, index: CaseIndex | None, label: str = "") -> LinkChip:
    u = urlparse(value)
    chip = LinkChip(url=value, label=label or ((u.hostname or "").removeprefix("www.") + u.path.rstrip("/")))
    hit = index.find(value, kind) if index else None
    if hit is not None:
        chip.entity_id = hit.id
        chip.state = "target" if hit.is_seed else ("confirmed" if hit.confirmed_flag else "found")
    return chip


def counts(ev: Evidence) -> tuple[int, int]:
    return len(ev.for_), len(ev.against)
