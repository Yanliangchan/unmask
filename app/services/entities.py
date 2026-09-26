from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Entity, EntityObservation, Relation, ScanRun


@dataclass
class EntityFilters:
    type: str | None = None
    min_confidence: float = 0.0
    tools: list[str] = field(default_factory=list)
    confirmed_only: bool = False


@dataclass
class EntityRow:
    entity: Entity
    sources: list[str]
    failed_sources: list[str]


async def list_entities(session: AsyncSession, case_id: uuid.UUID, filters: EntityFilters) -> list[EntityRow]:
    stmt = select(Entity).where(Entity.case_id == case_id, Entity.merged_into_id.is_(None))
    if filters.type:
        stmt = stmt.where(Entity.type == filters.type)
    if filters.min_confidence > 0:
        stmt = stmt.where(Entity.confidence >= filters.min_confidence)
    if filters.confirmed_only:
        stmt = stmt.where(Entity.confirmed_flag.is_(True))
    if filters.tools:
        stmt = stmt.where(
            Entity.id.in_(select(EntityObservation.entity_id).where(EntityObservation.source_tool.in_(filters.tools)))
            | Entity.source_tool.in_(filters.tools)
        )
    stmt = stmt.order_by(Entity.is_seed.desc(), Entity.confidence.desc(), Entity.first_seen.desc())
    entities = (await session.scalars(stmt)).all()
    if not entities:
        return []

    sources: dict[uuid.UUID, set[str]] = {e.id: {e.source_tool} for e in entities}
    obs = await session.execute(
        select(EntityObservation.entity_id, EntityObservation.source_tool).where(
            EntityObservation.entity_id.in_(sources.keys())
        )
    )
    for entity_id, tool in obs.all():
        sources[entity_id].add(tool)

    latest_run = await session.scalar(
        select(ScanRun).where(ScanRun.case_id == case_id).order_by(ScanRun.run_number.desc()).limit(1)
    )
    failed = set(latest_run.tools_failed) if latest_run else set()
    return [
        EntityRow(entity=e, sources=sorted(sources[e.id]), failed_sources=sorted(sources[e.id] & failed))
        for e in entities
    ]


@dataclass
class RelationView:
    relation: Relation
    other: Entity
    direction: str  # "out" | "in"


async def entity_detail(session: AsyncSession, case_id: uuid.UUID, entity_id: uuid.UUID):
    entity = await session.scalar(select(Entity).where(Entity.id == entity_id, Entity.case_id == case_id))
    if entity is None:
        return None, [], []
    rels = (
        await session.scalars(
            select(Relation).where((Relation.entity_a_id == entity.id) | (Relation.entity_b_id == entity.id))
        )
    ).all()
    other_ids = {r.entity_b_id if r.entity_a_id == entity.id else r.entity_a_id for r in rels}
    others = {e.id: e for e in (await session.scalars(select(Entity).where(Entity.id.in_(other_ids)))).all()}
    views = [
        RelationView(
            relation=r,
            other=others[r.entity_b_id if r.entity_a_id == entity.id else r.entity_a_id],
            direction="out" if r.entity_a_id == entity.id else "in",
        )
        for r in rels
        if (r.entity_b_id if r.entity_a_id == entity.id else r.entity_a_id) in others
    ]
    observations = (
        await session.execute(
            select(EntityObservation, ScanRun.run_number)
            .join(ScanRun, ScanRun.id == EntityObservation.scan_run_id)
            .where(EntityObservation.entity_id == entity.id)
            .order_by(ScanRun.run_number)
        )
    ).all()
    return entity, views, observations
