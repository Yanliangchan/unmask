"""Case graph for the Cytoscape view.

Merged values collapse into their surviving entity, relations are re-pointed
accordingly, and analyst "not the same" decisions are left out. Node size is
PageRank centrality, computed here so the browser only draws.
"""

from __future__ import annotations

import uuid
from collections import defaultdict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.engine import NOT_SAME, SAME_AS
from app.models import Entity, PivotLog, Relation, ScanRun

MAX_LABEL = 42


def pagerank(nodes: list[uuid.UUID], edges: list[tuple[uuid.UUID, uuid.UUID]], iterations: int = 40) -> dict:
    """Undirected PageRank, normalised so the most central node is 1.0."""
    if not nodes:
        return {}
    neighbours: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    for a, b in edges:
        neighbours[a].add(b)
        neighbours[b].add(a)
    n, damping = len(nodes), 0.85
    rank = dict.fromkeys(nodes, 1.0 / n)
    for _ in range(iterations):
        dangling = sum(rank[v] for v in nodes if not neighbours[v]) / n
        rank = {
            v: (1 - damping) / n + damping * (dangling + sum(rank[u] / len(neighbours[u]) for u in neighbours[v]))
            for v in nodes
        }
    top = max(rank.values()) or 1.0
    return {v: round(r / top, 4) for v, r in rank.items()}


def _label(value: str) -> str:
    return value if len(value) <= MAX_LABEL else value[: MAX_LABEL - 1] + "…"


async def case_graph(session: AsyncSession, case_id: uuid.UUID) -> dict:
    entities = (await session.scalars(select(Entity).where(Entity.case_id == case_id))).all()
    owner = {e.id: (e.merged_into_id or e.id) for e in entities}
    active = {e.id: e for e in entities if e.merged_into_id is None}
    merged_count: dict[uuid.UUID, int] = defaultdict(int)
    for e in entities:
        if e.merged_into_id:
            merged_count[e.merged_into_id] += 1

    pivot_runs = set(
        (
            await session.scalars(
                select(ScanRun.id).where(ScanRun.case_id == case_id, ScanRun.triggered_by == "pivot_chain")
            )
        ).all()
    )
    triggered = set(
        (
            await session.scalars(
                select(PivotLog.triggering_entity_id).where(
                    PivotLog.case_id == case_id, PivotLog.scan_run_id.is_not(None)
                )
            )
        ).all()
    )
    via_pivot = {owner[e.id] for e in entities if e.scan_run_id in pivot_runs}

    edges: dict[tuple, dict] = {}
    for r in (await session.scalars(select(Relation).where(Relation.case_id == case_id))).all():
        if r.relation_type in (SAME_AS, NOT_SAME):
            continue
        a, b = owner.get(r.entity_a_id), owner.get(r.entity_b_id)
        if a is None or b is None or a == b:
            continue
        key = (a, b, r.relation_type)
        if key not in edges:
            edges[key] = {
                "id": str(r.id),
                "source": str(a),
                "target": str(b),
                "type": r.relation_type,
                "label": r.relation_type.replace("_", " "),
                "via": r.source_tool,
                "suggested": r.relation_type == "possible_same",
            }
    centrality = pagerank(list(active), [(k[0], k[1]) for k in edges])

    nodes = [
        {
            "id": str(e.id),
            "label": _label(e.value),
            "value": e.value,
            "type": e.type,
            "confidence": round(e.confidence, 3),
            "confirmed": e.confirmed_flag,
            "seed": e.is_seed,
            "pivot": e.id in via_pivot or e.id in triggered,
            "merged": merged_count[e.id],
            "centrality": centrality.get(e.id, 0.0),
        }
        for e in active.values()
    ]
    return {"nodes": nodes, "edges": list(edges.values())}
