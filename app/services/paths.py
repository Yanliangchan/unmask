"""Evidence-weighted paths between two findings.

A path is only as good as its links, so every link gets a weight from how it was
established and how confident it is, every intermediate finding is discounted by
how much it is a hub (a shared provider or a common name connects everything),
and every extra hop costs. Paths are ranked by the product, which is a measure
of *association strength through the collected evidence* — never of identity.

    w(edge) = basis weight × (0.5 + 0.5 × confidence)   [× 0.6 for an unreviewed possible duplicate]
    n(node) = √belief × log₂4 / log₂(2 + degree)          (intermediate findings; targets count 1)
    score   = Π w × Π n × 0.85^(hops − 1)

The top paths come from Yen's k-shortest-paths on cost = −log(score), so the
ranking is exact for this score. Each path reports its weakest link and what it
is made of (observed vs inferred), so an analyst can see what the chain rests on.
"""

from __future__ import annotations

import heapq
import math
from dataclasses import dataclass, field

BASIS_WEIGHT = {"analyst": 1.0, "observed": 0.9, "rule": 0.75, "similarity": 0.45}
SUGGESTED_FACTOR = 0.6
HOP_DECAY = 0.85
MAX_HOPS = 6
HUB_DEGREE = 10
LONG_CHAIN = 3
CAVEAT = (
    "A path shows how findings are connected through the collected evidence. It is not proof that "
    "they belong to the same person: check the weakest link before relying on it."
)


def edge_weight(edge: dict) -> float:
    w = BASIS_WEIGHT.get(edge.get("basis") or "observed", 0.6)
    c = edge.get("confidence")
    w *= 0.5 + 0.5 * (min(max(float(c), 0.0), 1.0) if c is not None else 0.5)
    if edge.get("suggested"):
        w *= SUGGESTED_FACTOR
    return max(w, 1e-6)


def node_factor(node: dict) -> float:
    if node.get("seed"):
        return 1.0  # a target links to everything found from it by construction; that is not hubness
    belief = 1.0 if node.get("seed") or node.get("confirmed") else max(float(node.get("confidence") or 0.0), 0.05)
    degree = max(int(node.get("degree") or 0), 2)
    return math.sqrt(belief) * 2.0 / math.log2(2 + degree)


@dataclass
class Path:
    nodes: list[str]
    edges: list[str]
    score: float
    weakest: str | None
    weakest_weight: float
    observed: int
    inferred: int
    flags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "nodes": self.nodes, "edges": self.edges, "score": round(self.score, 4), "hops": len(self.edges),
            "weakest": self.weakest, "weakest_weight": round(self.weakest_weight, 3),
            "observed": self.observed, "inferred": self.inferred, "flags": self.flags,
        }  # fmt: skip


class _Graph:
    def __init__(self, graph: dict, include_suggested: bool):
        self.nodes = {n["id"]: n for n in graph["nodes"]}
        self.edges = {e["id"]: e for e in graph["edges"] if include_suggested or not e.get("suggested")}
        self.adj: dict[str, list[tuple[str, str]]] = {n: [] for n in self.nodes}
        for e in self.edges.values():
            if e["source"] in self.adj and e["target"] in self.adj:
                # Direction records where a link was found, not which way identity flows: walk both ways.
                self.adj[e["source"]].append((e["target"], e["id"]))
                self.adj[e["target"]].append((e["source"], e["id"]))
        self.w = {eid: edge_weight(e) for eid, e in self.edges.items()}

    def step_cost(self, eid: str, to: str, end: str) -> float:
        cost = -math.log(self.w[eid])
        if to != end:
            cost -= math.log(min(node_factor(self.nodes[to]), 1.0))
        return cost

    def shortest(self, start, end, banned_nodes=frozenset(), banned_edges=frozenset()):
        dist = {start: 0.0}
        prev: dict[str, tuple[str, str]] = {}
        heap = [(0.0, start, 0)]
        while heap:
            d, v, hops = heapq.heappop(heap)
            if v == end:
                break
            if d > dist.get(v, math.inf) or hops >= MAX_HOPS:
                continue
            for to, eid in self.adj[v]:
                if to in banned_nodes or eid in banned_edges:
                    continue
                nd = d + self.step_cost(eid, to, end) - math.log(HOP_DECAY)
                if nd < dist.get(to, math.inf):
                    dist[to], prev[to] = nd, (v, eid)
                    heapq.heappush(heap, (nd, to, hops + 1))
        if end not in prev:
            return None
        nodes, edges, v = [end], [], end
        while v != start:
            v, eid = prev[v]
            nodes.append(v)
            edges.append(eid)
        return nodes[::-1], edges[::-1]

    def cost(self, nodes: list[str], edges: list[str]) -> float:
        return sum(self.step_cost(e, nodes[i + 1], nodes[-1]) - math.log(HOP_DECAY) for i, e in enumerate(edges))


def find_paths(graph: dict, source: str, target: str, k: int = 5, include_suggested: bool = True) -> dict:
    g = _Graph(graph, include_suggested)
    if source not in g.nodes or target not in g.nodes or source == target:
        return {"paths": [], "caveat": CAVEAT}
    first = g.shortest(source, target)
    if first is None:
        return {"paths": [], "caveat": CAVEAT}
    found = [first]
    candidates: list[tuple[float, tuple, tuple]] = []
    seen = {tuple(first[1])}
    while len(found) < k:
        nodes, edges = found[-1]
        for i in range(len(nodes) - 1):
            root_nodes, root_edges = nodes[: i + 1], edges[:i]
            banned_edges = {p[1][i] for p in found if p[0][: i + 1] == root_nodes and len(p[1]) > i}
            spur = g.shortest(nodes[i], target, frozenset(root_nodes[:-1]), frozenset(banned_edges))
            if spur is None:
                continue
            total = (root_nodes[:-1] + spur[0], root_edges + spur[1])
            if len(total[1]) > MAX_HOPS or tuple(total[1]) in seen:
                continue
            seen.add(tuple(total[1]))
            heapq.heappush(candidates, (g.cost(*total), tuple(total[0]), tuple(total[1])))
        if not candidates:
            break
        _, n, e = heapq.heappop(candidates)
        found.append((list(n), list(e)))
    return {"paths": [_describe(g, n, e).as_dict() for n, e in found], "caveat": CAVEAT}


def _describe(g: _Graph, nodes: list[str], edges: list[str]) -> Path:
    score = math.exp(-g.cost(nodes, edges))
    weakest = min(edges, key=lambda e: g.w[e]) if edges else None
    observed = sum(1 for e in edges if g.edges[e].get("basis") in ("observed", "analyst"))
    flags = []
    if len(edges) > LONG_CHAIN:
        flags.append(f"long chain ({len(edges)} links): each extra link is another assumption")
    inner = [g.nodes[v] for v in nodes[1:-1] if not g.nodes[v].get("seed")]
    hubs = [n for n in inner if (n.get("degree") or 0) >= HUB_DEGREE]
    if hubs:
        flags.append(f"passes through a hub ({hubs[0]['label']}): many unrelated findings connect there")
    if any(g.edges[e].get("basis") == "similarity" for e in edges):
        flags.append("rests on a similarity match, which suggests but does not establish a link")
    if any(g.edges[e].get("suggested") for e in edges):
        flags.append("includes a possible duplicate nobody has reviewed")
    return Path(nodes, edges, score, weakest, g.w[weakest] if weakest else 1.0, observed, len(edges) - observed, flags)
