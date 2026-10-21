"""Case graph for the graph workspace.

Merged values collapse into their surviving entity, relations are re-pointed
accordingly, and analyst "not the same" decisions are left out. Every relation
behind an edge is kept as evidence on that edge (who or what established it,
how, when, and how often it was seen), so the browser can explain a link
without another request. Node size is PageRank centrality, computed here so
the browser only draws.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation.engine import CORROBORATING, NOT_SAME, SAME_AS
from app.models import Entity, EntityObservation, PivotLog, Relation, ScanRun

MAX_LABEL = 42
# Above this many findings the weakest stay off the first view (the page offers them).
MAX_NODES = 1500
MAX_EVIDENCE = 12
# Strongest first: an edge is as well established as its best piece of evidence.
BASIS_RANK = {"analyst": 4, "observed": 3, "rule": 2, "similarity": 1, "imported": 0}


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


def components(nodes: list[uuid.UUID], edges: list[tuple[uuid.UUID, uuid.UUID]]) -> dict[uuid.UUID, int]:
    """Connected components, numbered from the largest (0) down."""
    parent = {v: v for v in nodes}

    def find(v):
        while parent[v] != v:
            parent[v] = parent[parent[v]]
            v = parent[v]
        return v

    for a, b in edges:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb
    groups: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    for v in nodes:
        groups[find(v)].append(v)
    ordered = sorted(groups.values(), key=len, reverse=True)
    return {v: i for i, members in enumerate(ordered) for v in members}


def _label(value: str) -> str:
    return value if len(value) <= MAX_LABEL else value[: MAX_LABEL - 1] + "…"


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def edge_key(a: uuid.UUID, b: uuid.UUID, rtype: str, directed: bool) -> tuple:
    """One edge per pair and type. Undirected links match in either order; a directed one keeps its order."""
    if not directed and str(b) < str(a):
        a, b = b, a
    return (a, b, rtype)


async def case_graph(session: AsyncSession, case_id: uuid.UUID, include_all: bool = False) -> dict:
    entities = (await session.scalars(select(Entity).where(Entity.case_id == case_id))).all()
    owner = {e.id: (e.merged_into_id or e.id) for e in entities}
    # Findings the analyst ruled out ("Not them") are left off the graph.
    active = {e.id: e for e in entities if e.merged_into_id is None and not e.dismissed_flag}
    merged_count: dict[uuid.UUID, int] = defaultdict(int)
    for e in entities:
        if e.merged_into_id:
            merged_count[e.merged_into_id] += 1

    # Which tools saw each finding (merged members included), and when last.
    sources: dict[uuid.UUID, set[str]] = defaultdict(set)
    last_seen: dict[uuid.UUID, datetime] = {}
    rows = await session.execute(
        select(EntityObservation.entity_id, EntityObservation.source_tool, func.max(EntityObservation.observed_at))
        .join(Entity, Entity.id == EntityObservation.entity_id)
        .where(Entity.case_id == case_id)
        .group_by(EntityObservation.entity_id, EntityObservation.source_tool)
    )
    for entity_id, tool, seen in rows:
        own = owner.get(entity_id, entity_id)
        sources[own].add(tool)
        if own not in last_seen or seen > last_seen[own]:
            last_seen[own] = seen
    for e in entities:
        sources[owner[e.id]].add(e.source_tool)

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
        key = edge_key(a, b, r.relation_type, r.directed)
        evidence = {
            "tool": r.source_tool,
            "why": r.match_explanation or "",
            "confidence": round(float(r.confidence), 3) if r.confidence is not None else None,
            "basis": r.basis,
            "by": "analyst" if r.created_by.startswith("analyst") else r.created_by,
            "first_seen": _iso(r.created_at),
            "last_seen": _iso(r.last_seen),
            "seen": r.seen_count,
        }
        ed = edges.get(key)
        if ed is None:
            ed = edges[key] = {
                "id": "|".join(map(str, key)),
                "source": str(key[0]),
                "target": str(key[1]),
                "type": r.relation_type,
                "label": r.relation_type.replace("_", " "),
                "kind": _edge_kind(r.relation_type),
                "suggested": r.relation_type == "possible_same",
                "directed": r.directed,
                "basis": r.basis,
                "confidence": evidence["confidence"] or 0.0,
                "first_seen": evidence["first_seen"],
                "last_seen": evidence["last_seen"],
                "seen": 0,
                "via": r.source_tool,
                "why": evidence["why"],
                "relation": str(r.id),  # the strongest record behind this edge, for pinning
                "evidence": [],
            }
        ed["seen"] += r.seen_count
        ed["first_seen"] = min(filter(None, [ed["first_seen"], evidence["first_seen"]]), default=None)
        ed["last_seen"] = max(filter(None, [ed["last_seen"], evidence["last_seen"]]), default=None)
        if BASIS_RANK.get(r.basis, 0) > BASIS_RANK.get(ed["basis"], 0):
            ed["basis"] = r.basis
        if (evidence["confidence"] or 0) > ed["confidence"]:
            ed["confidence"], ed["why"], ed["via"] = evidence["confidence"], evidence["why"], r.source_tool
            ed["relation"] = str(r.id)
        if len(ed["evidence"]) < MAX_EVIDENCE:
            ed["evidence"].append(evidence)
    pairs = [(k[0], k[1]) for k in edges]
    centrality = pagerank(list(active), pairs)
    degree: dict[uuid.UUID, int] = defaultdict(int)
    for a, b in {tuple(sorted(p, key=str)) for p in pairs}:
        degree[a] += 1
        degree[b] += 1

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
    out_edges = [ed for ed in edges.values() if uuid.UUID(ed["source"]) in kept and uuid.UUID(ed["target"]) in kept]
    cluster = components(list(kept), [(uuid.UUID(ed["source"]), uuid.UUID(ed["target"])) for ed in out_edges])

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
            "degree": degree[e.id],
            "cluster": cluster.get(e.id, 0),
            "sources": sorted(sources[e.id]),
            "reliability": e.source_reliability,
            "first_seen": _iso(e.first_seen),
            "last_seen": _iso(last_seen.get(e.id) or e.last_verified),
        }
        for e in shown
    ]
    runs = (await session.scalars(select(ScanRun).where(ScanRun.case_id == case_id).order_by(ScanRun.run_number))).all()
    return {
        "nodes": nodes,
        "edges": out_edges,
        "hidden": trimmed,
        "clusters": len(set(cluster.values())),
        # When each scan ended, for replaying the case scan by scan ("as of scan 3").
        "scans": [{"number": r.run_number, "at": _iso(r.completed_at or r.created_at)} for r in runs],
    }


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
