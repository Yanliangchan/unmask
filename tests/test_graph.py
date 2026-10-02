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
    db.add(
        Relation(case_id=case.id, entity_a_id=a.id, entity_b_id=b.id, relation_type=rtype,
                 source_tool="fake_ok", created_by=created_by)
    )  # fmt: skip


async def _case(db):
    owner = await db.scalar(select(User).where(User.email == "admin@example.com"))
    case = await create_case(
        db, owner=owner, name=f"Graph {uuid.uuid4().hex[:6]}", authorization_note="graph test",
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
