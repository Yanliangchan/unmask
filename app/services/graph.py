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

from app.correlation.engine import CORROBORATING, NOT_SAME, SAME_AS
from app.models import Entity, PivotLog, Relation, ScanRun

MAX_LABEL = 42
MAX_NODES = 400


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


async def case_graph(session: AsyncSession, case_id: uuid.UUID, include_all: bool = False) -> dict:
    entities = (await session.scalars(select(Entity).where(Entity.case_id == case_id))).all()
    owner = {e.id: (e.merged_into_id or e.id) for e in entities}
    # Findings the analyst ruled out ("Not them") are left off the graph.
    active = {e.id: e for e in entities if e.merged_into_id is None and not e.dismissed_flag}
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
        if a is None or b is None or a == b or a not in active or b not in active:
            continue
        key = (a, b, r.relation_type)
        if key not in edges:
            edges[key] = {
                "id": str(r.id),
                "source": str(a),
                "target": str(b),
                "type": r.relation_type,
                "label": r.relation_type.replace("_", " "),
                "kind": _edge_kind(r.relation_type),
                "why": (r.match_explanation or "")[:200],
                "confidence": round(float(r.confidence or 0.0), 3),
                "via": r.source_tool,
                "suggested": r.relation_type == "possible_same",
            }
    centrality = pagerank(list(active), [(k[0], k[1]) for k in edges])

    # Large cases: weak and unchecked findings stay off the first view, so the
    # graph stays readable; the page offers to show them.
    shown = list(active.values())
    trimmed = 0
    if len(shown) > MAX_NODES and not include_all:
        keep = [e for e in shown if _strength(e) in ("target", "confirmed", "likely", "possible")]
        keep.sort(key=lambda e: (not e.is_seed, not e.confirmed_flag, -e.confidence))
        keep = keep[:MAX_NODES]
        trimmed = len(shown) - len(keep)
        shown = keep
    kept = {e.id for e in shown}

    nodes = [
        {
            "id": str(e.id),
            "label": _label(e.value),
            "value": e.value,
            "type": e.type,
            "site": (e.attributes or {}).get("site") or "",
            "confidence": round(e.confidence, 3),
            "strength": _strength(e),
            "verification": e.verification or "",
            "confirmed": e.confirmed_flag,
            "seed": e.is_seed,
            "pivot": e.id in via_pivot or e.id in triggered,
            "merged": merged_count[e.id],
            "centrality": centrality.get(e.id, 0.0),
        }
        for e in shown
    ]
    out_edges = [ed for ed in edges.values() if uuid.UUID(ed["source"]) in kept and uuid.UUID(ed["target"]) in kept]
    return {"nodes": nodes, "edges": out_edges, "hidden": trimmed}


def _strength(e: Entity) -> str:
    from app.services.entities import LIKELY, POSSIBLE

    if e.is_seed:
        return "target"
    if e.confirmed_flag:
        return "confirmed"
    if e.verification == "unverified":
        return "unchecked"
    return "likely" if e.confidence >= LIKELY else "possible" if e.confidence >= POSSIBLE else "unlikely"


def _edge_kind(relation_type: str) -> str:
    """How an edge is drawn: strong evidence, a plain "found via" link, or a possible duplicate."""
    if relation_type == "possible_same":
        return "suggested"
    if relation_type in CORROBORATING:
        return "strong"
    return "link"
