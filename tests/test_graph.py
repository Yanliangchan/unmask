import uuid

from sqlalchemy import select

from app import crypto
from app.correlation import engine
from app.models import Entity, Relation, User
from app.services.cases import TargetInput, create_case
from app.services.graph import case_graph, pagerank
from tests.conftest import login


def test_pagerank_ranks_the_hub_highest():
    hub, a, b, c, lone = (uuid.uuid4() for _ in range(5))
    ranks = pagerank([hub, a, b, c, lone], [(hub, a), (hub, b), (hub, c)])
    assert ranks[hub] == 1.0
    assert ranks[a] == ranks[b] == ranks[c] < 1.0
    assert 0 < ranks[lone] < ranks[a]


def _add(db, case, etype, value, confidence=0.5, **kw):
    e = Entity(
        case_id=case.id, type=etype, value=value, value_digest=crypto.digest(etype, value),
        attributes={}, source_tool="fake_ok", confidence=confidence, field_confidence={"prior": confidence},
        source_reliability="C", **kw,
    )  # fmt: skip
    db.add(e)
    return e


def _rel(db, case, a, b, rtype, created_by="engine"):
    # Like persist_candidates: a tool's link runs from what was searched to what was found.
    observed = rtype not in (engine.POSSIBLE_SAME, engine.NOT_SAME, engine.SAME_AS)
    db.add(
        Relation(case_id=case.id, entity_a_id=a.id, entity_b_id=b.id, relation_type=rtype, source_tool="fake_ok",
                 created_by=created_by, directed=observed,
                 basis="analyst" if created_by.startswith("analyst") else "observed" if observed else "similarity")
    )  # fmt: skip


async def _case(db):
    owner = await db.scalar(select(User).where(User.email == "admin@example.com"))
    case = await create_case(
        db, owner=owner, name=f"Graph {uuid.uuid4().hex[:6]}", authorization_note="Graph test: engagement ref G-1",
        lawful_basis_confirmed=True, targets=[TargetInput("graphuser", "username")], disabled_tools=[],
    )  # fmt: skip
    await db.flush()
    return case


async def test_graph_collapses_merges_and_hides_rejected_pairs(db):
    case = await _case(db)
    seed = await db.scalar(select(Entity).where(Entity.case_id == case.id, Entity.is_seed.is_(True)))
    gh = _add(db, case, "account", "https://github.com/graphuser")
    gh_dup = _add(db, case, "account", "https://www.github.com/graphuser/")
    other = _add(db, case, "account", "https://gitlab.com/graphuser")
    name_a, name_b = _add(db, case, "name", "Jon Smith"), _add(db, case, "name", "John Smith")
    await db.flush()
    _rel(db, case, seed, gh, "has_account")
    _rel(db, case, seed, gh_dup, "has_account")  # points at the value that will be merged away
    _rel(db, case, seed, other, "has_account")
    _rel(db, case, name_a, name_b, "possible_same")
    _rel(db, case, gh, other, engine.NOT_SAME, created_by="analyst:x")
    await db.flush()
    await engine.merge_entities(db, gh, gh_dup, created_by="engine", explanation="dup")
    await db.flush()

    graph = await case_graph(db, case.id)
    node_ids = {n["id"] for n in graph["nodes"]}
    assert str(gh_dup.id) not in node_ids and str(gh.id) in node_ids
    gh_node = next(n for n in graph["nodes"] if n["id"] == str(gh.id))
    assert gh_node["merged"] == 1
    types = [(e["source"], e["target"], e["type"]) for e in graph["edges"]]
    # The merged member's edge is re-pointed and de-duplicated, not drawn twice.
    assert types.count((str(seed.id), str(gh.id), "has_account")) == 1
    assert not any(t == engine.NOT_SAME or t == engine.SAME_AS for _, _, t in types)
    assert any(e["suggested"] for e in graph["edges"])
    seed_node = next(n for n in graph["nodes"] if n["id"] == str(seed.id))
    assert seed_node["seed"] and seed_node["centrality"] == 1.0


async def test_graph_endpoint_is_private(client, db):
    csrf = await login(client)
    case = await _case(db)
    await db.commit()
    r = await client.get(f"/cases/{case.id}/graph.json")
    assert r.status_code == 200 and r.json()["nodes"][0]["type"] == "username"
    assert r.headers["cache-control"] == "no-store"
    tab = await client.get(f"/cases/{case.id}/tab/graph")
    assert 'data-graph="/cases/' in tab.text and "/static/js/graph.js" in tab.text
    await client.post("/logout", data={"csrf_token": csrf})
    assert (await client.get(f"/cases/{case.id}/graph.json")).status_code == 303


async def test_graph_nodes_carry_strength_and_edges_say_why(db):
    case = await _case(db)
    seed = await db.scalar(select(Entity).where(Entity.case_id == case.id, Entity.is_seed.is_(True)))
    strong = _add(db, case, "account", "https://github.com/graphuser", verification="verified", confidence=0.85)
    weak = _add(db, case, "account", "https://forum.example/graphuser", verification="unverified", confidence=0.3)
    await db.flush()
    _rel(db, case, seed, strong, "has_account")
    db.add(
        Relation(case_id=case.id, entity_a_id=strong.id, entity_b_id=weak.id, relation_type="shares_handle",
                 source_tool="correlation", created_by="engine", match_explanation="same handle 'graphuser'")
    )  # fmt: skip
    await db.flush()

    graph = await case_graph(db, case.id)
    by_id = {n["id"]: n for n in graph["nodes"]}
    assert by_id[str(seed.id)]["strength"] == "target"
    assert by_id[str(strong.id)]["strength"] == "likely" and by_id[str(strong.id)]["verification"] == "verified"
    assert by_id[str(weak.id)]["strength"] == "unchecked"
    kinds = {e["type"]: e for e in graph["edges"]}
    assert kinds["shares_handle"]["kind"] == "strong" and kinds["shares_handle"]["why"] == "same handle 'graphuser'"
    assert kinds["has_account"]["kind"] == "link"
    assert graph["hidden"] == 0


async def test_large_graphs_leave_weak_findings_out_until_asked(db, monkeypatch):
    from app.services import graph as graph_mod

    monkeypatch.setattr(graph_mod, "MAX_NODES", 3)
    case = await _case(db)
    for i in range(3):
        _add(db, case, "account", f"https://site{i}.example/graphuser", verification="verified", confidence=0.8)
    for i in range(4):
        _add(db, case, "account", f"https://weak{i}.example/graphuser", verification="unverified", confidence=0.2)
    await db.flush()
    trimmed = await case_graph(db, case.id)
    assert len(trimmed["nodes"]) == 3 and trimmed["hidden"] == 5
    assert all(n["strength"] in ("target", "likely") for n in trimmed["nodes"])
    assert len((await case_graph(db, case.id, include_all=True))["nodes"]) == 8


# --- Evidence on edges and path analysis -------------------------------------------------------


async def test_parallel_relations_become_one_edge_with_all_their_evidence(db):
    case = await _case(db)
    seed = await db.scalar(select(Entity).where(Entity.case_id == case.id, Entity.is_seed.is_(True)))
    name_a, name_b = _add(db, case, "name", "Jane Roe"), _add(db, case, "name", "Jane R. Roe")
    await db.flush()
    for a, b, why, conf in [(name_a, name_b, "86% name similarity", 0.86), (name_b, name_a, "embedding 0.91", 0.91)]:
        db.add(Relation(case_id=case.id, entity_a_id=a.id, entity_b_id=b.id, relation_type="possible_same",
                        source_tool="correlation", match_explanation=why, confidence=conf,
                        basis="similarity"))  # fmt: skip
    _rel(db, case, seed, name_a, "has_account")
    await db.flush()
    graph = await case_graph(db, case.id)
    dup = [e for e in graph["edges"] if e["type"] == "possible_same"]
    assert len(dup) == 1  # either order is the same undirected link
    assert dup[0]["confidence"] == 0.91 and dup[0]["why"] == "embedding 0.91"
    assert {ev["why"] for ev in dup[0]["evidence"]} == {"86% name similarity", "embedding 0.91"}
    assert dup[0]["basis"] == "similarity" and not dup[0]["directed"]
    found = next(e for e in graph["edges"] if e["type"] == "has_account")
    assert found["directed"] and found["basis"] == "observed" and found["source"] == str(seed.id)
    node = next(n for n in graph["nodes"] if n["id"] == str(name_a.id))
    assert node["sources"] == ["fake_ok"] and node["degree"] == 2 and graph["clusters"] == 1


def _g(nodes, edges):
    return {
        "nodes": [{"id": n, "label": n, "confidence": c, "degree": d, "seed": n == "seed"} for n, c, d in nodes],
        "edges": [{"id": f"{a}-{b}", "source": a, "target": b, "basis": basis, "confidence": conf,
                   "suggested": basis == "similarity"} for a, b, basis, conf in edges],
    }  # fmt: skip


def test_paths_prefer_observed_links_over_a_shorter_guess():
    from app.services.paths import find_paths

    graph = _g(
        [("seed", 1, 2), ("gh", 0.8, 2), ("site", 0.8, 2), ("x", 0.5, 2)],
        [
            ("seed", "gh", "observed", 0.8),
            ("gh", "site", "observed", 0.9),  # two observed links
            ("seed", "x", "similarity", 0.5),
            ("x", "site", "similarity", 0.5),
        ],  # fmt: skip
    )
    result = find_paths(graph, "seed", "site")
    best, alt = result["paths"][0], result["paths"][1]
    assert best["nodes"] == ["seed", "gh", "site"] and best["observed"] == 2 and best["inferred"] == 0
    assert alt["score"] < best["score"] and any("similarity" in f for f in alt["flags"])
    assert alt["weakest"] in ("seed-x", "x-site")
    assert "not proof" in result["caveat"]


def test_paths_through_a_hub_are_discounted_and_flagged():
    from app.services.paths import find_paths

    graph = _g(
        [("seed", 1, 2), ("gmail.com", 0.9, 40), ("other", 0.7, 2), ("via", 0.7, 2)],
        [
            ("seed", "gmail.com", "observed", 0.9),
            ("gmail.com", "other", "observed", 0.9),
            ("seed", "via", "observed", 0.7),
            ("via", "other", "observed", 0.7),
        ],  # fmt: skip
    )
    paths = find_paths(graph, "seed", "other")["paths"]
    assert paths[0]["nodes"] == ["seed", "via", "other"]
    assert any("hub" in f for f in paths[1]["flags"])


def test_no_path_between_disconnected_findings():
    from app.services.paths import find_paths

    graph = _g([("seed", 1, 1), ("a", 0.5, 1), ("b", 0.5, 1)], [("seed", "a", "observed", 0.5)])
    assert find_paths(graph, "seed", "b")["paths"] == []
    assert find_paths(graph, "seed", "seed")["paths"] == []


async def test_paths_endpoint_is_private(client, db):
    csrf = await login(client)
    case = await _case(db)
    await db.commit()
    seed = await db.scalar(select(Entity).where(Entity.case_id == case.id, Entity.is_seed.is_(True)))
    r = await client.get(f"/cases/{case.id}/paths.json", params={"a": str(seed.id), "b": str(uuid.uuid4())})
    assert r.status_code == 200 and r.json()["paths"] == []
    await client.post("/logout", data={"csrf_token": csrf})
    assert (await client.get(f"/cases/{case.id}/paths.json?a=x&b=y")).status_code == 303


def test_a_target_in_the_middle_of_a_path_is_not_called_a_hub():
    from app.services.paths import find_paths

    graph = _g([("a", 0.8, 2), ("seed", 1, 30), ("b", 0.8, 2)],
               [("a", "seed", "observed", 0.8), ("seed", "b", "observed", 0.8)])  # fmt: skip
    path = find_paths(graph, "a", "b")["paths"][0]
    assert path["nodes"] == ["a", "seed", "b"] and not any("hub" in f for f in path["flags"])
