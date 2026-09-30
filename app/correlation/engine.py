"""Two-pass correlation over one case.

Pass 1 (string rules, rapidfuzz)
  * **Merge** entities that are the same identifier written differently
    (canonical forms equal, or a name that differs only by order, case or
    punctuation). This is de-duplication, not an identity judgement.
  * **Link** entities across types when their values corroborate each other
    (an email whose handle is the username, a profile name matching a name).
  * **Suggest** near-misses (e.g. ``jdoe`` vs ``j.doe``, 85–95% name similarity).

Pass 2 (local sentence embeddings)
  * **Suggest** semantically similar names/usernames the string rules missed.

Only pass 1's same-identifier rule merges automatically. Everything that is a
judgement about identity becomes a ``possible_same`` suggestion with a written
explanation, for an analyst to accept (merge) or dismiss. Analyst decisions
(``same_as``/``not_same`` created by ``analyst``) are never overridden.
"""

from __future__ import annotations

import inspect
import itertools
import json
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from rapidfuzz import fuzz
from sqlalchemy import delete, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.correlation import normalize as norm
from app.correlation.embeddings import EmbeddingError, cosine, get_embedder
from app.correlation.scoring import Evidence, score, tag_match_score
from app.models import Entity, EntityObservation, Relation, Target

SAME_AS = "same_as"
POSSIBLE_SAME = "possible_same"
NOT_SAME = "not_same"
# Cross-field links that count as corroboration in the confidence score.
CORROBORATING = {"shares_handle", "profile_name_match", "email_at_domain", "breach_associated", "profile_links_to"}

ENGINE = "correlation"
SUGGEST_RATIO = 85
HANDLE_SUGGEST_RATIO = 90
PROFILE_NAME_RATIO = 90

# Internal/echo keys that must not count as "details" when matching context tags.
_TAG_IGNORE = {
    "origin",
    "context_tags",
    "_score_explanation",
    "url",
    "host",
    "email",
    "domain",
    "username",
    "verification",
    "verification_reason",
}


@dataclass
class CorrelationResult:
    merged: int = 0
    linked: int = 0
    suggested: int = 0
    rescored: int = 0
    pass2: str = ""
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"{self.merged} merged, {self.linked} linked, {self.suggested} suggested for review, "
            f"{self.rescored} rescored; pass 2: {self.pass2}"
        )


def _pair(a: uuid.UUID, b: uuid.UUID) -> tuple[uuid.UUID, uuid.UUID]:
    return (a, b) if str(a) < str(b) else (b, a)


class _Graph:
    """In-memory view of the case's relations for de-duplication."""

    def __init__(self, relations: list[Relation]):
        self.by_pair: dict[tuple[uuid.UUID, uuid.UUID], set[str]] = defaultdict(set)
        for r in relations:
            self.by_pair[_pair(r.entity_a_id, r.entity_b_id)].add(r.relation_type)

    def has(self, a: uuid.UUID, b: uuid.UUID, *types: str) -> bool:
        return bool(self.by_pair.get(_pair(a, b), set()) & set(types))

    def add(self, a: uuid.UUID, b: uuid.UUID, rtype: str) -> None:
        self.by_pair[_pair(a, b)].add(rtype)

    def blocked(self, a: uuid.UUID, b: uuid.UUID) -> bool:
        """An analyst said these differ, or they are already merged/suggested."""
        return self.has(a, b, NOT_SAME, SAME_AS, POSSIBLE_SAME)


async def lock_case(session: AsyncSession, case_id: uuid.UUID) -> None:
    await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": str(case_id)})


# --- Merge / split (used by the engine and by analysts) ------------------------


def pool_attributes(keep: dict | None, extra: dict | None) -> dict:
    """Combine details from merged values; the survivor's own values win conflicts.

    Without this a merge would throw away evidence the other value carried
    (e.g. a profile's name and location), weakening correlation and scoring.
    """
    keep, extra = dict(keep or {}), dict(extra or {})
    pooled = {**extra, **keep}
    for key in ("profile", "fields"):
        if isinstance(keep.get(key), dict) or isinstance(extra.get(key), dict):
            pooled[key] = {**(extra.get(key) or {}), **(keep.get(key) or {})}
    pooled.pop("_score_explanation", None)
    return pooled


def _winner(a: Entity, b: Entity) -> tuple[Entity, Entity]:
    """Targets outrank discoveries, confirmed outrank unconfirmed, older outranks newer."""
    rank_a = (not a.is_seed, not a.confirmed_flag, a.first_seen)
    rank_b = (not b.is_seed, not b.confirmed_flag, b.first_seen)
    return (a, b) if rank_a <= rank_b else (b, a)


async def merge_entities(session: AsyncSession, a: Entity, b: Entity, *, created_by: str, explanation: str) -> Entity:
    """Merge two same-type entities; returns the surviving entity."""
    if a.type != b.type:
        raise ValueError("only entities of the same type can be merged")
    if a.id == b.id:
        raise ValueError("cannot merge an entity with itself")
    winner, loser = _winner(a, b)
    # Flatten: anything already merged into the loser now points at the winner.
    members = (await session.scalars(select(Entity).where(Entity.merged_into_id == loser.id))).all()
    for m in members:
        m.merged_into_id = winner.id
    loser.merged_into_id = winner.id
    winner.attributes = pool_attributes(winner.attributes, loser.attributes)
    winner.confirmed_flag = winner.confirmed_flag or loser.confirmed_flag
    winner.first_seen = min(winner.first_seen, loser.first_seen)
    winner.last_verified = max(winner.last_verified, loser.last_verified)
    winner.source_reliability = min(winner.source_reliability, loser.source_reliability)
    await session.execute(
        delete(Relation).where(
            Relation.relation_type == POSSIBLE_SAME,
            ((Relation.entity_a_id == a.id) & (Relation.entity_b_id == b.id))
            | ((Relation.entity_a_id == b.id) & (Relation.entity_b_id == a.id)),
        )
    )
    first, second = _pair(winner.id, loser.id)
    session.add(
        Relation(
            case_id=winner.case_id,
            entity_a_id=first,
            entity_b_id=second,
            relation_type=SAME_AS,
            source_tool=ENGINE if created_by == "engine" else "analyst",
            match_explanation=explanation,
            confidence=1.0,
            created_by=created_by,
        )
    )
    await session.flush()
    return winner


async def split_entity(session: AsyncSession, member: Entity, *, created_by: str, explanation: str) -> Entity:
    """Detach a merged member and record that it must not be re-merged."""
    if member.merged_into_id is None:
        raise ValueError("entity is not merged into another")
    winner_id = member.merged_into_id
    member.merged_into_id = None
    await session.execute(
        delete(Relation).where(
            Relation.relation_type.in_((SAME_AS, POSSIBLE_SAME)),
            ((Relation.entity_a_id == winner_id) & (Relation.entity_b_id == member.id))
            | ((Relation.entity_a_id == member.id) & (Relation.entity_b_id == winner_id)),
        )
    )
    first, second = _pair(winner_id, member.id)
    session.add(
        Relation(
            case_id=member.case_id,
            entity_a_id=first,
            entity_b_id=second,
            relation_type=NOT_SAME,
            source_tool="analyst",
            match_explanation=explanation,
            confidence=1.0,
            created_by=created_by,
        )
    )
    await session.flush()
    return member


async def dismiss_suggestion(session: AsyncSession, relation: Relation, *, created_by: str) -> None:
    if relation.relation_type != POSSIBLE_SAME:
        raise ValueError("not a suggestion")
    relation.relation_type = NOT_SAME
    relation.source_tool = "analyst"
    relation.created_by = created_by
    relation.match_explanation = f"dismissed by analyst (was: {relation.match_explanation})"
    await session.flush()


# --- The engine ------------------------------------------------------------------


def _link(session, graph, case_id, a: Entity, b: Entity, rtype: str, explanation: str, confidence: float) -> bool:
    if a.id == b.id or graph.has(a.id, b.id, rtype) or graph.has(a.id, b.id, NOT_SAME):
        return False
    first, second = _pair(a.id, b.id)
    session.add(
        Relation(
            case_id=case_id,
            entity_a_id=first,
            entity_b_id=second,
            relation_type=rtype,
            source_tool=ENGINE,
            match_explanation=explanation,
            confidence=confidence,
            created_by="engine",
        )
    )
    graph.add(a.id, b.id, rtype)
    return True


def _detail_text(entity: Entity) -> str:
    attrs = {k: v for k, v in (entity.attributes or {}).items() if k not in _TAG_IGNORE}
    return json.dumps(attrs, default=str, ensure_ascii=False)


# "Jane Doe (janedoe) · GitHub", "Jane Doe - Medium", "Jane Doe | LinkedIn" -> "Jane Doe"
_TITLE_SUFFIX = re.compile(r"\s+[·•|/–—:\-]\s+[^·•|/–—:]{1,40}$|\s*\([^)]*\)$|\s+@\S+$")
_NOT_A_NAME = re.compile(r"^(?:profile|user|posts?|about|account|member|overview|page)\b", re.I)


def _title_name(title: str, handle: str) -> str | None:
    name = title.strip()
    for _ in range(3):
        stripped = _TITLE_SUFFIX.sub("", name).strip()
        # "janedoe (Jane Doe) · GitHub": the handle comes first and the name is in brackets.
        if handle and norm.handle(stripped) == norm.handle(handle) and (m := re.search(r"\(([^)]+)\)\s*$", name)):
            name = m.group(1).strip()
            break
        name = stripped
    words = name.split()
    # A display name: 2-5 words, mostly letters, and not just the handle again.
    if not 2 <= len(words) <= 5 or sum(ch.isalpha() for ch in name) < 0.8 * len(name.replace(" ", "")):
        return None
    if _NOT_A_NAME.match(name) or (handle and norm.handle(name) == norm.handle(handle)):
        return None
    return name


def _profile_names(entity: Entity) -> list[str]:
    attrs = entity.attributes or {}
    profile = attrs.get("profile") or {}
    names = [str(profile[k]) for k in ("fullname", "name") if profile.get(k)]
    # A checked profile page's title usually carries the display name.
    if entity.verification == "verified":
        title = (attrs.get("preview") or {}).get("title") or ""
        if title and (name := _title_name(str(title), str(attrs.get("username") or ""))):
            names.append(name)
    return names


def _link_targets(entity: Entity) -> tuple[list[str], list[str]]:
    preview = (entity.attributes or {}).get("preview") or {}
    if entity.verification != "verified":
        return [], []
    return list(preview.get("links") or []), list(preview.get("emails") or [])


def _url_key(url: str) -> str:
    from urllib.parse import urlparse

    p = urlparse(url.strip())
    host = (p.hostname or "").lower().removeprefix("www.")
    return f"{host}{p.path.rstrip('/')}".lower()


async def correlate_case(session: AsyncSession, case_id: uuid.UUID, *, semantic: bool = True) -> CorrelationResult:
    """Run both passes and rescore every entity. Caller commits.

    ``semantic=False`` skips pass 2 (embeddings): used for the quick rescore
    after each tool finishes, so results show up scored while a scan runs.
    """
    await lock_case(session, case_id)
    result = CorrelationResult()
    # Deterministic order: the oldest entity of a duplicate group survives.
    entities = list(
        (
            await session.scalars(
                select(Entity).where(Entity.case_id == case_id).order_by(Entity.first_seen, Entity.id)
            )
        ).all()
    )
    relations = list((await session.scalars(select(Relation).where(Relation.case_id == case_id))).all())
    graph = _Graph(relations)
    active = [e for e in entities if e.merged_into_id is None]

    # Pass 1a — same identifier written differently: merge.
    by_canonical: dict[tuple[str, str], list[Entity]] = defaultdict(list)
    for e in active:
        by_canonical[(e.type, norm.canonical(e.type, e.value))].append(e)
    for (etype, _canon), group in by_canonical.items():
        if len(group) < 2:
            continue
        survivor = group[0]
        for other in group[1:]:
            if graph.has(survivor.id, other.id, NOT_SAME):
                continue
            previous = survivor
            survivor = await merge_entities(
                session,
                survivor,
                other,
                created_by="engine",
                explanation=f"same {etype}: '{previous.value}' and '{other.value}' have the same canonical form",
            )
            graph.add(previous.id, other.id, SAME_AS)
            result.merged += 1
    active = [e for e in active if e.merged_into_id is None]

    by_type: dict[str, list[Entity]] = defaultdict(list)
    for e in active:
        by_type[e.type].append(e)

    # Pass 1b — close name variants ("Jon Smith"/"John Smith", "Yan Chan"/"Yan Liang Chan")
    # are suggested, never merged: a different spelling may be a different person.
    for a, b in itertools.combinations(by_type.get("name", []), 2):
        if graph.blocked(a.id, b.id):
            continue
        ratio = fuzz.ratio(norm.canonical_name(a.value), norm.canonical_name(b.value))
        compatible = norm.initials_compatible(a.value, b.value)
        if ratio >= SUGGEST_RATIO or (compatible and ratio >= 60):
            why = f"'{a.value}' vs '{b.value}': {ratio:.0f}% name similarity"
            why += ", initials compatible" if compatible else ", initials differ"
            if _link(session, graph, case_id, a, b, POSSIBLE_SAME, why, ratio / 100):
                result.suggested += 1

    # Pass 1c — usernames that differ only by separators or a few characters.
    for a, b in itertools.combinations(by_type.get("username", []), 2):
        if graph.blocked(a.id, b.id):
            continue
        if norm.handle(a.value) == norm.handle(b.value):
            why = f"'{a.value}' and '{b.value}' are the same handle with different separators"
            if _link(session, graph, case_id, a, b, POSSIBLE_SAME, why, 0.9):
                result.suggested += 1
            continue
        ratio = fuzz.ratio(norm.fold(a.value), norm.fold(b.value))
        if ratio >= HANDLE_SUGGEST_RATIO:
            why = f"'{a.value}' vs '{b.value}': {ratio:.0f}% string similarity"
            if _link(session, graph, case_id, a, b, POSSIBLE_SAME, why, ratio / 100):
                result.suggested += 1

    # Pass 1d — cross-field corroboration links.
    usernames = by_type.get("username", [])
    for email in by_type.get("email", []):
        handle = norm.email_handle(email.value)
        for user in usernames:
            if handle and handle == norm.handle(user.value):
                why = f"email handle of '{email.value}' matches username '{user.value}'"
                if _link(session, graph, case_id, email, user, "shares_handle", why, 0.7):
                    result.linked += 1
        domain = email.value.rsplit("@", 1)[-1].casefold()
        for d in by_type.get("domain", []):
            if norm.canonical("domain", d.value) == domain:
                if _link(session, graph, case_id, email, d, "email_at_domain", f"address is at {d.value}", 0.8):
                    result.linked += 1
    for account in by_type.get("account", []):
        for pname in _profile_names(account):
            for name in by_type.get("name", []):
                ratio = fuzz.ratio(norm.canonical_name(pname), norm.canonical_name(name.value))
                if ratio >= PROFILE_NAME_RATIO and norm.initials_compatible(pname, name.value):
                    why = f"profile name '{pname}' on {account.attributes.get('site')} matches '{name.value}'"
                    if _link(session, graph, case_id, account, name, "profile_name_match", why, ratio / 100):
                        result.linked += 1

    # A checked profile that links to another account, the target's domain or an email in the case.
    by_url = {_url_key(e.value): e for e in by_type.get("account", []) + by_type.get("web_mention", [])}
    for account in by_type.get("account", []):
        links, emails = _link_targets(account)
        site = account.attributes.get("site") or "profile"
        for link in links:
            other = by_url.get(_url_key(link))
            if other is not None and other.id != account.id:
                why = f"the {site} profile links to {other.value}"
                if _link(session, graph, case_id, account, other, "profile_links_to", why, 0.9):
                    result.linked += 1
            host = _url_key(link).split("/", 1)[0]
            for d in by_type.get("domain", []):
                dom = norm.canonical("domain", d.value)
                if host == dom or host.endswith("." + dom):
                    why = f"the {site} profile links to {d.value}"
                    if _link(session, graph, case_id, account, d, "profile_links_to", why, 0.9):
                        result.linked += 1
        for addr in emails:
            for email in by_type.get("email", []):
                if norm.canonical("email", email.value) == norm.canonical("email", addr):
                    why = f"the {site} profile lists {email.value}"
                    if _link(session, graph, case_id, account, email, "profile_links_to", why, 0.9):
                        result.linked += 1

    # Pass 2 — semantic similarity for names and usernames the rules missed.
    embedder, reason = get_embedder() if semantic else (None, "runs when the scan finishes")
    candidates = by_type.get("name", []) + by_type.get("username", [])
    if embedder is None:
        result.pass2 = f"skipped ({reason})"
    elif len(candidates) < 2:
        result.pass2 = f"ran with {embedder.name}; nothing to compare"
    else:
        threshold = get_settings().embedding_threshold
        try:
            vectors = embedder.embed([e.value for e in candidates])
            if inspect.isawaitable(vectors):
                vectors = await vectors
        except EmbeddingError as exc:
            vectors = None
            result.pass2 = f"skipped ({exc})"
        found = 0
        for (i, a), (j, b) in itertools.combinations(enumerate(candidates), 2) if vectors else ():
            if graph.blocked(a.id, b.id) or graph.has(a.id, b.id, *CORROBORATING):
                continue
            if a.type != b.type:
                continue
            sim = cosine(vectors[i], vectors[j])
            if sim < threshold:
                continue
            why = f"'{a.value}' vs '{b.value}': embedding similarity {sim:.2f} ({embedder.name})"
            if a.type == "name":
                compatible = norm.initials_compatible(a.value, b.value)
                why += ", initials compatible" if compatible else ", initials differ"
            if _link(session, graph, case_id, a, b, POSSIBLE_SAME, why, round(sim, 4)):
                found += 1
        result.suggested += found
        if vectors is not None:
            result.pass2 = f"ran with {embedder.name}; {found} suggestion(s)"

    await session.flush()
    result.rescored = await rescore_case(session, case_id)
    return result


async def rescore_case(session: AsyncSession, case_id: uuid.UUID) -> int:
    entities = list((await session.scalars(select(Entity).where(Entity.case_id == case_id))).all())
    active = {e.id: e for e in entities if e.merged_into_id is None}
    members: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for e in entities:
        if e.merged_into_id is not None:
            members[e.merged_into_id].append(e.id)

    tools: dict[uuid.UUID, set[str]] = defaultdict(set)
    for e in entities:
        tools[e.merged_into_id or e.id].add(e.source_tool)
    owner = {e.id: (e.merged_into_id or e.id) for e in entities}
    obs = await session.execute(
        select(EntityObservation.entity_id, EntityObservation.source_tool).where(
            EntityObservation.entity_id.in_(list(owner))
        )
    )
    for entity_id, tool in obs.all():
        tools[owner[entity_id]].add(tool)

    corroborations: dict[uuid.UUID, list[str]] = defaultdict(list)
    rels = (
        await session.scalars(
            select(Relation).where(Relation.case_id == case_id, Relation.relation_type.in_(CORROBORATING))
        )
    ).all()
    for r in rels:
        for eid in (owner.get(r.entity_a_id), owner.get(r.entity_b_id)):
            if eid is not None:
                corroborations[eid].append(r.relation_type.replace("_", " "))

    tags: list[str] = []
    for t in (await session.scalars(select(Target).where(Target.case_id == case_id))).all():
        tags.extend(t.context_tags or [])

    from app.correlation.commonness import username_rarity
    from app.services.accuracy import site_factor, site_host, site_stats

    stats = await site_stats(session)
    for e in active.values():
        attrs = e.attributes or {}
        rarity, rarity_note, factor, site_note = None, "", 1.0, None
        if e.type == "account":
            if e.site_host is None:
                e.site_host = site_host(e.value)  # backfills accounts stored before the column existed
            # Linked accounts are evidence through the link, not a username coincidence.
            if attrs.get("username") and not attrs.get("linked_from"):
                rarity, rarity_note = username_rarity(str(attrs["username"]))
            factor, site_note = site_factor(stats.get(e.site_host or ""))
        ev = Evidence(
            prior=float((e.field_confidence or {}).get("prior", e.confidence)),
            reliability=e.source_reliability,
            sources=len(tools[e.id] - {"analyst"}) or 1,
            corroborations=sorted(set(corroborations[e.id])),
            tag_match=None if e.is_seed else tag_match_score(tags, _detail_text(e)),
            is_seed=e.is_seed,
            confirmed=e.confirmed_flag,
            verification=e.verification,
            rarity=rarity,
            rarity_note=rarity_note,
            site_factor=factor,
            site_note=site_note,
        )
        s = score(ev)
        adapter_fields = {k: v for k, v in (e.field_confidence or {}).items() if not k.startswith("evidence.")}
        e.confidence = s.overall
        e.field_confidence = {**adapter_fields, **s.components}
        e.tag_match_score = ev.tag_match
        e.attributes = {**(e.attributes or {}), "_score_explanation": s.explanation}
    await session.flush()
    return len(active)


async def correlate_and_commit(
    session: AsyncSession, case_id: uuid.UUID, *, semantic: bool = True
) -> CorrelationResult:
    result = await correlate_case(session, case_id, semantic=semantic)
    await session.commit()
    return result
