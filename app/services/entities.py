from __future__ import annotations

import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from rapidfuzz import fuzz
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.engine import POSSIBLE_SAME
from app.correlation.normalize import fold
from app.models import Entity, EntityObservation, Relation, ScanRun

# Below this, an unconfirmed finding is left out of the default view.
WEAK_CONFIDENCE = 0.3
# Plain-language match strength: Likely / Possible / Unlikely.
LIKELY, POSSIBLE = 0.7, 0.45
SHOW_MODES = ("best", "all", "confirmed", "dismissed")


def hidden_reason(e: Entity) -> str | None:
    """Why the default ("best") view leaves this entity out, if it does."""
    if e.dismissed_flag:
        return "dismissed"
    if e.is_seed or e.confirmed_flag:
        return None
    if e.type == "account" and e.verification == "unverified":
        return "unverified"
    if e.confidence < WEAK_CONFIDENCE:
        return "weak"
    return None


@dataclass
class EntityFilters:
    type: str | None = None
    min_confidence: float = 0.0
    tools: list[str] = field(default_factory=list)
    confirmed_only: bool = False
    q: str = ""  # case-insensitive substring of the value
    # best: hide unverified accounts and weak findings | all | confirmed | dismissed
    show: str = "best"


@dataclass
class EntityList:
    rows: list[EntityRow]
    # What the chosen view left out, by reason (dismissed / unverified / weak).
    hidden: Counter = field(default_factory=Counter)


@dataclass
class EntityRow:
    entity: Entity
    sources: list[str]
    failed_sources: list[str]
    merged_count: int = 0
    suggestion_count: int = 0


async def _sources_by_owner(session: AsyncSession, entities: list[Entity]) -> dict[uuid.UUID, set[str]]:
    """Tools that reported each canonical entity, including its merged members."""
    owner = {e.id: (e.merged_into_id or e.id) for e in entities}
    sources: dict[uuid.UUID, set[str]] = defaultdict(set)
    for e in entities:
        sources[owner[e.id]].add(e.source_tool)
    if owner:
        obs = await session.execute(
            select(EntityObservation.entity_id, EntityObservation.source_tool).where(
                EntityObservation.entity_id.in_(list(owner))
            )
        )
        for entity_id, tool in obs.all():
            sources[owner[entity_id]].add(tool)
    return sources


async def list_entities(session: AsyncSession, case_id: uuid.UUID, filters: EntityFilters) -> list[EntityRow]:
    return (await list_entities_view(session, case_id, filters)).rows


async def list_entities_view(session: AsyncSession, case_id: uuid.UUID, filters: EntityFilters) -> EntityList:
    all_entities = list((await session.scalars(select(Entity).where(Entity.case_id == case_id))).all())
    sources = await _sources_by_owner(session, all_entities)
    merged_count: dict[uuid.UUID, int] = defaultdict(int)
    for e in all_entities:
        if e.merged_into_id:
            merged_count[e.merged_into_id] += 1
    suggestions: dict[uuid.UUID, int] = defaultdict(int)
    for a, b in (
        await session.execute(
            select(Relation.entity_a_id, Relation.entity_b_id).where(
                Relation.case_id == case_id, Relation.relation_type == POSSIBLE_SAME
            )
        )
    ).all():
        suggestions[a] += 1
        suggestions[b] += 1

    rows = []
    hidden: Counter = Counter()
    for e in all_entities:
        if e.merged_into_id is not None:
            continue
        reason = hidden_reason(e)
        if filters.show == "dismissed":
            if reason != "dismissed":
                continue
        elif reason == "dismissed" or (filters.show == "best" and reason):
            hidden[reason] += 1
            continue
        if filters.show == "confirmed" and not (e.confirmed_flag or e.is_seed):
            continue
        if filters.type and e.type != filters.type:
            continue
        if e.confidence < filters.min_confidence:
            continue
        if filters.confirmed_only and not e.confirmed_flag:
            continue
        if filters.tools and not (sources[e.id] & set(filters.tools)):
            continue
        if filters.q and filters.q.casefold() not in e.value.casefold():
            continue
        rows.append(e)
    rows.sort(key=lambda e: (not e.is_seed, -e.confidence, -e.first_seen.timestamp()))

    latest_run = await session.scalar(
        select(ScanRun).where(ScanRun.case_id == case_id).order_by(ScanRun.run_number.desc()).limit(1)
    )
    failed = set(latest_run.tools_failed) if latest_run else set()
    return EntityList(
        rows=[
            EntityRow(
                entity=e,
                sources=sorted(sources[e.id]),
                failed_sources=sorted(sources[e.id] & failed),
                merged_count=merged_count[e.id],
                suggestion_count=suggestions[e.id],
            )
            for e in rows
        ],
        hidden=hidden,
    )


@dataclass
class RelationView:
    relation: Relation
    other: Entity
    direction: str  # "out" | "in"


@dataclass
class EntityDetail:
    entity: Entity
    relations: list[RelationView]
    members: list[Entity]
    observations: list
    merged_into: Entity | None = None


async def entity_detail(session: AsyncSession, case_id: uuid.UUID, entity_id: uuid.UUID) -> EntityDetail | None:
    entity = await session.scalar(select(Entity).where(Entity.id == entity_id, Entity.case_id == case_id))
    if entity is None:
        return None
    members = list(
        (
            await session.scalars(select(Entity).where(Entity.merged_into_id == entity.id).order_by(Entity.first_seen))
        ).all()
    )
    ids = [entity.id, *(m.id for m in members)]
    rels = (
        await session.scalars(select(Relation).where(Relation.entity_a_id.in_(ids) | Relation.entity_b_id.in_(ids)))
    ).all()
    other_ids = {(r.entity_b_id if r.entity_a_id in ids else r.entity_a_id) for r in rels}
    others = {e.id: e for e in (await session.scalars(select(Entity).where(Entity.id.in_(other_ids)))).all()}
    views = []
    for r in rels:
        other_id = r.entity_b_id if r.entity_a_id in ids else r.entity_a_id
        if other_id in ids or other_id not in others:
            continue  # links inside the merge group are shown as members
        views.append(RelationView(r, others[other_id], "out" if r.entity_a_id in ids else "in"))
    views.sort(key=lambda v: (v.relation.relation_type != POSSIBLE_SAME, v.relation.relation_type))
    observations = (
        await session.execute(
            select(EntityObservation, ScanRun.run_number)
            .join(ScanRun, ScanRun.id == EntityObservation.scan_run_id)
            .where(EntityObservation.entity_id.in_(ids))
            .order_by(ScanRun.run_number)
        )
    ).all()
    merged_into = await session.get(Entity, entity.merged_into_id) if entity.merged_into_id else None
    return EntityDetail(entity, views, members, observations, merged_into)


@dataclass
class Suggestion:
    relation: Relation
    a: Entity
    b: Entity


async def list_suggestions(session: AsyncSession, case_id: uuid.UUID) -> list[Suggestion]:
    rels = (
        await session.scalars(
            select(Relation)
            .where(Relation.case_id == case_id, Relation.relation_type == POSSIBLE_SAME)
            .order_by(Relation.confidence.desc())
        )
    ).all()
    ids = {r.entity_a_id for r in rels} | {r.entity_b_id for r in rels}
    entities = {e.id: e for e in (await session.scalars(select(Entity).where(Entity.id.in_(ids)))).all()}
    return [
        Suggestion(r, entities[r.entity_a_id], entities[r.entity_b_id])
        for r in rels
        if r.entity_a_id in entities
        and r.entity_b_id in entities
        and not entities[r.entity_a_id].merged_into_id
        and not entities[r.entity_b_id].merged_into_id
    ]


async def merge_candidates(session: AsyncSession, entity: Entity, limit: int = 25) -> list[tuple[Entity, float]]:
    """Same-type entities in the case, most similar first."""
    others = (
        await session.scalars(
            select(Entity).where(
                Entity.case_id == entity.case_id,
                Entity.type == entity.type,
                Entity.id != entity.id,
                Entity.merged_into_id.is_(None),
            )
        )
    ).all()
    ranked = [(o, fuzz.WRatio(fold(entity.value), fold(o.value))) for o in others]
    ranked.sort(key=lambda pair: -pair[1])
    return ranked[:limit]
