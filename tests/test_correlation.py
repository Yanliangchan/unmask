"""Correlation engine: canonical forms, scoring, both passes and analyst overrides.

The synthetic near-duplicate fixtures pin the merge rules down, so tuning a
threshold can't silently change what gets merged.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from app import crypto
from app.correlation import engine
from app.correlation import normalize as norm
from app.correlation.embeddings import set_embedder
from app.correlation.scoring import Evidence, score, tag_match_score
from app.models import AccessLog, Entity, Relation, User
from app.services.cases import TargetInput, create_case
from tests.conftest import login

# --- Canonical forms ---------------------------------------------------------------


@pytest.mark.parametrize(
    "etype, a, b",
    [
        ("email", "Jane.Doe@Example.com", "jane.doe@example.com"),
        ("email", "jane.doe+news@gmail.com", "janedoe@googlemail.com"),
        ("account", "https://www.github.com/JDoe/", "http://github.com/jdoe"),
        ("hostname", "Mail.Example.com.", "mail.example.com"),
        ("name", "Chan, Yan-Liang", "yan liang chan"),
        ("name", "José Ramírez", "Jose Ramirez"),
        ("phone", "+65 9123 4567", "+6591234567"),
        ("ip", "2001:db8::0:1", "2001:db8::1"),
    ],
)
def test_same_identifier_written_differently(etype, a, b):
    assert norm.canonical(etype, a) == norm.canonical(etype, b)


@pytest.mark.parametrize(
    "etype, a, b",
    [
        ("email", "jane.doe@example.com", "janedoe@example.com"),  # dots only ignored at Gmail
        ("email", "jdoe@example.com", "jdoe@example.org"),
        ("username", "jdoe", "jdoe1"),
        ("name", "Jon Smith", "John Smith"),
        ("account", "https://github.com/jdoe", "https://gitlab.com/jdoe"),
    ],
)
def test_different_identifiers_stay_different(etype, a, b):
    assert norm.canonical(etype, a) != norm.canonical(etype, b)


@pytest.mark.parametrize(
    "a, b, ok",
    [
        ("J. Chan", "John Chan", True),
        ("J. Chan", "Yan Liang Chan", False),
        ("Yan Chan", "Yan Liang Chan", True),
        ("Y. L. Chan", "Yan Liang Chan", True),
        ("Mary Chan", "Yan Liang Chan", False),
    ],
)
def test_initials_compatibility(a, b, ok):
    assert norm.initials_compatible(a, b) is ok


# --- Scoring ------------------------------------------------------------------------


def test_more_independent_sources_raise_confidence():
    one = score(Evidence(prior=0.4, reliability="C", sources=1)).overall
    three = score(Evidence(prior=0.4, reliability="C", sources=3)).overall
    assert three > one


def test_reliability_changes_how_far_the_prior_is_trusted():
    trusted = score(Evidence(prior=0.6, reliability="B", sources=1)).overall
    dump = score(Evidence(prior=0.6, reliability="D", sources=1)).overall
    assert trusted > dump


def test_corroboration_and_tags_raise_confidence_with_diminishing_returns():
    base = score(Evidence(prior=0.4, reliability="C", sources=1)).overall
    one = score(Evidence(prior=0.4, reliability="C", sources=1, corroborations=["a"])).overall
    capped = score(Evidence(prior=0.4, reliability="C", sources=1, corroborations=list("abcdef"))).overall
    tagged = score(Evidence(prior=0.4, reliability="C", sources=1, tag_match=1.0)).overall
    assert base < one < capped < 0.99
    assert tagged > base
    assert capped - one < one - base + 0.2  # capped at three corroborations


def test_human_decisions_outrank_the_score():
    assert score(Evidence(prior=0.1, reliability="E", sources=1, confirmed=True)).overall == 1.0
    assert score(Evidence(prior=0.1, reliability="E", sources=1, is_seed=True)).overall == 1.0


def test_score_explains_itself():
    s = score(Evidence(prior=0.4, reliability="C", sources=2, corroborations=["shares handle"], tag_match=0.5))
    text = " ".join(s.explanation)
    assert "2 independent tools" in text and "shares handle" in text and "50%" in text


def test_tag_matching():
    assert tag_match_score(["singapore", "fintech"], '{"location": "Singapore", "bio": "Fintech engineer"}') == 1.0
    assert tag_match_score(["singapore", "fintech"], '{"location": "Berlin"}') == 0.0
    assert tag_match_score(["sg"], "anything") is None  # too short to match meaningfully
    assert tag_match_score([], "x") is None


# --- Engine (needs the database) ---------------------------------------------------


class FakeEmbedder:
    """Deterministic stand-in for the sentence-transformer model."""

    name = "fake-embedder"
    # Pairs a real model scores as semantically close.
    CLUSTERS = [{"j. chan", "yan liang chan"}, {"bill gates", "william gates"}]

    def embed(self, texts):
        vectors = []
        for t in texts:
            v = [0.0] * (len(self.CLUSTERS) + 1)
            idx = next((i for i, c in enumerate(self.CLUSTERS) if t.casefold() in c), len(self.CLUSTERS))
            v[idx] = 1.0
            if idx == len(self.CLUSTERS):
                v.append(hash(t) % 97 + 1.0)  # unrelated strings: orthogonal-ish
            else:
                v.append(0.0)
            vectors.append(v)
        return vectors


@pytest.fixture
def fake_embedder():
    set_embedder(FakeEmbedder())
    yield
    set_embedder(None, "disabled in tests")


@pytest.fixture(autouse=True)
def _no_embedder_by_default():
    set_embedder(None, "disabled in tests")
    yield


async def new_case(db, targets=None, tags=None):
    owner = await db.scalar(select(User).where(User.email == "admin@example.com"))
    case = await create_case(
        db,
        owner=owner,
        name=f"Correlation {uuid.uuid4().hex[:6]}",
        authorization_note="correlation test",
        lawful_basis_confirmed=True,
        targets=targets or [TargetInput(value="yanliang", type="username", context_tags=tags or [])],
        disabled_tools=[],
    )
    await db.flush()
    return case


def add(db, case, etype, value, *, tool="fake_ok", prior=0.4, reliability="C", attributes=None, **kw):
    e = Entity(
        case_id=case.id,
        type=etype,
        value=value,
        value_digest=crypto.digest(etype, value),
        attributes=attributes or {},
        source_tool=tool,
        confidence=prior,
        field_confidence={"prior": prior},
        source_reliability=reliability,
        **kw,
    )
    db.add(e)
    return e


async def relations(db, case_or_id, rtype=None):
    case_id = case_or_id if isinstance(case_or_id, uuid.UUID) else case_or_id.id
    stmt = select(Relation).where(Relation.case_id == case_id)
    if rtype:
        stmt = stmt.where(Relation.relation_type == rtype)
    return list((await db.scalars(stmt)).all())


async def test_same_identifiers_merge_with_explanations(db):
    t0 = datetime.now(UTC)
    case = await new_case(db)
    a = add(db, case, "account", "https://www.github.com/YanLiang", first_seen=t0)
    b = add(db, case, "account", "https://github.com/yanliang/", tool="maigret", first_seen=t0 + timedelta(1))
    c = add(db, case, "email", "Yan.Liang+x@gmail.com", first_seen=t0)
    d = add(db, case, "email", "yanliang@googlemail.com", tool="holehe", first_seen=t0 + timedelta(1))
    keep = add(db, case, "account", "https://gitlab.com/yanliang")
    await db.flush()

    result = await engine.correlate_case(db, case.id)
    assert result.merged == 2
    assert (b.merged_into_id, d.merged_into_id) == (a.id, c.id)  # older entity survives
    assert keep.merged_into_id is None
    same = await relations(db, case, engine.SAME_AS)
    assert len(same) == 2 and all("canonical form" in r.match_explanation for r in same)
    # Merging pooled the sources: two tools now back the GitHub account.
    assert a.field_confidence["evidence.sources"] == 2.0
    assert a.confidence > keep.confidence


async def test_merge_pools_details_so_evidence_is_not_lost(db):
    t0 = datetime.now(UTC)
    case = await new_case(db, tags=["singapore"])
    bare = add(db, case, "account", "https://www.github.com/yanliang", attributes={"site": "GitHub"}, first_seen=t0)
    profile = {"fullname": "Yan-Liang Chan", "location": "Singapore"}
    rich = add(
        db, case, "account", "https://github.com/yanliang", tool="maigret", first_seen=t0 + timedelta(1),
        attributes={"site": "GitHub", "profile": profile},
    )  # fmt: skip
    add(db, case, "name", "Yan Liang Chan")
    await db.flush()
    await engine.correlate_case(db, case.id)
    assert rich.merged_into_id == bare.id
    assert bare.attributes["profile"]["location"] == "Singapore"
    assert bare.tag_match_score == 1.0
    assert "profile_name_match" in {r.relation_type for r in await relations(db, case)}


async def test_name_variants_are_suggested_never_merged(db):
    case = await new_case(db)
    a = add(db, case, "name", "Jon Smith")
    b = add(db, case, "name", "John Smith")
    c = add(db, case, "name", "Yan Chan")
    d = add(db, case, "name", "Yan Liang Chan")
    unrelated = add(db, case, "name", "Mary Poppins")
    await db.flush()

    result = await engine.correlate_case(db, case.id)
    assert result.merged == 0
    assert all(e.merged_into_id is None for e in (a, b, c, d, unrelated))
    pairs = {frozenset((r.entity_a_id, r.entity_b_id)) for r in await relations(db, case, engine.POSSIBLE_SAME)}
    assert frozenset((a.id, b.id)) in pairs
    assert frozenset((c.id, d.id)) in pairs
    assert not any(unrelated.id in p for p in pairs)


async def test_username_separator_variants_are_suggested(db):
    case = await new_case(db)
    a = add(db, case, "username", "j.doe")
    b = add(db, case, "username", "j_doe")
    c = add(db, case, "username", "someoneelse")
    await db.flush()
    await engine.correlate_case(db, case.id)
    suggestions = await relations(db, case, engine.POSSIBLE_SAME)
    assert len(suggestions) == 1
    assert {suggestions[0].entity_a_id, suggestions[0].entity_b_id} == {a.id, b.id}
    assert "different separators" in suggestions[0].match_explanation
    assert c.merged_into_id is None


async def test_cross_field_corroboration_links_and_raises_confidence(db):
    case = await new_case(db)
    email = add(db, case, "email", "yanliang@example.com", prior=0.5)
    control = add(db, case, "email", "other@example.com", prior=0.5)
    name = add(db, case, "name", "Yan Liang Chan", prior=0.3, reliability="D")
    account = add(db, case, "account", "https://github.com/yanliang", attributes={
        "site": "GitHub", "profile": {"fullname": "Yan-Liang Chan"}})  # fmt: skip
    await db.flush()

    await engine.correlate_case(db, case.id)
    types = {r.relation_type for r in await relations(db, case)}
    assert {"shares_handle", "profile_name_match"} <= types
    assert email.confidence > control.confidence
    assert "corroborated: shares handle" in email.attributes["_score_explanation"]
    assert account.field_confidence["evidence.corroborations"] == 1.0
    assert name.confidence > 0.3 * 0.8  # corroboration outweighs the D-rated prior


async def test_context_tags_feed_tag_match_score(db):
    case = await new_case(db, tags=["singapore", "fintech"])
    match = add(db, case, "account", "https://github.com/a", attributes={
        "site": "GitHub", "profile": {"location": "Singapore", "bio": "fintech"}})  # fmt: skip
    miss = add(db, case, "account", "https://github.com/b", attributes={"site": "GitHub", "profile": {}})
    await db.flush()
    await engine.correlate_case(db, case.id)
    assert match.tag_match_score == 1.0
    assert miss.tag_match_score == 0.0
    assert match.confidence > miss.confidence


async def test_correlation_is_idempotent(db):
    case = await new_case(db)
    add(db, case, "email", "a@example.com")
    add(db, case, "email", "A@EXAMPLE.com")
    add(db, case, "name", "Jon Smith")
    add(db, case, "name", "John Smith")
    await db.flush()
    await engine.correlate_case(db, case.id)
    first = sorted((r.relation_type, str(r.entity_a_id), str(r.entity_b_id)) for r in await relations(db, case))
    scores = {e.id: e.confidence for e in (await db.scalars(select(Entity).where(Entity.case_id == case.id))).all()}
    again = await engine.correlate_case(db, case.id)
    assert (again.merged, again.suggested, again.linked) == (0, 0, 0)
    assert sorted((r.relation_type, str(r.entity_a_id), str(r.entity_b_id)) for r in await relations(db, case)) == first
    rescored = (await db.scalars(select(Entity).where(Entity.case_id == case.id))).all()
    assert {e.id: e.confidence for e in rescored} == scores


async def test_pass2_suggests_semantic_matches_and_never_merges(db, fake_embedder):
    case = await new_case(db)
    a = add(db, case, "name", "J. Chan")
    b = add(db, case, "name", "Yan Liang Chan")
    c = add(db, case, "name", "Completely Different")
    await db.flush()
    result = await engine.correlate_case(db, case.id)
    assert "fake-embedder" in result.pass2
    assert a.merged_into_id is None and b.merged_into_id is None
    sugg = await relations(db, case, engine.POSSIBLE_SAME)
    assert len(sugg) == 1 and {sugg[0].entity_a_id, sugg[0].entity_b_id} == {a.id, b.id}
    # The explanation surfaces that the initials do not line up.
    assert "embedding similarity 1.00" in sugg[0].match_explanation
    assert "initials differ" in sugg[0].match_explanation
    assert c.id not in {sugg[0].entity_a_id, sugg[0].entity_b_id}


async def test_pass2_unavailable_is_reported_not_hidden(db):
    set_embedder(None, "sentence-transformers is not installed")
    case = await new_case(db)
    result = await engine.correlate_case(db, case.id)
    assert result.pass2 == "skipped (sentence-transformers is not installed)"


async def test_rescan_of_merged_value_does_not_resurrect_a_duplicate(db):
    from app.adapters.base import EntityCandidate
    from app.models import ScanRun, Target
    from app.services.scans import create_scan_run, persist_candidates

    case = await new_case(db)
    t0 = datetime.now(UTC)
    a = add(db, case, "account", "https://github.com/yanliang", first_seen=t0)
    b = add(db, case, "account", "https://www.github.com/yanliang/", first_seen=t0 + timedelta(1))
    await db.flush()
    await engine.correlate_case(db, case.id)
    assert b.merged_into_id == a.id
    run: ScanRun = await create_scan_run(db, case)
    target = await db.scalar(select(Target).where(Target.case_id == case.id))
    cand = EntityCandidate(type="account", value="https://www.github.com/yanliang/", confidence=0.4)
    await persist_candidates(db, run=run, target=target, tool="sherlock", candidates=[cand])
    await db.flush()
    accounts = (await db.scalars(select(Entity).where(Entity.case_id == case.id, Entity.type == "account"))).all()
    assert len(accounts) == 2  # still just the pair, no third copy


# --- Analyst overrides over HTTP -----------------------------------------------------


async def _case_via_http(client, db):
    csrf = await login(client)
    case = await new_case(db)
    await db.commit()
    return csrf, case


async def test_manual_merge_and_split_are_audited_and_respected(client, db):
    csrf, case = await _case_via_http(client, db)
    a = add(db, case, "username", "yanliang88")
    b = add(db, case, "username", "totally_other")
    await db.commit()
    a_id, b_id, case_id = a.id, b.id, case.id

    picker = await client.get(f"/cases/{case_id}/entities/{a_id}/merge")
    assert "totally_other" in picker.text
    r = await client.post(
        f"/cases/{case_id}/entities/{a_id}/merge", data={"other_id": str(b_id)}, headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 200 and "entities-changed" in r.headers["hx-trigger"]
    db.expire_all()
    merged = await db.get(Entity, b_id)
    assert merged.merged_into_id == a_id

    r = await client.post(f"/cases/{case_id}/entities/{b_id}/split", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    db.expire_all()
    assert (await db.get(Entity, b_id)).merged_into_id is None
    not_same = await relations(db, case_id, engine.NOT_SAME)
    assert len(not_same) == 1 and not_same[0].created_by.startswith("analyst:")

    actions = set((await db.scalars(select(AccessLog.action).where(AccessLog.case_id == case_id))).all())
    assert {"merge_entities", "split_entity"} <= actions

    # The engine never undoes the analyst's split, even for an obvious duplicate.
    b2 = await db.get(Entity, b_id)
    b2.value = "YANLIANG88"
    b2.value_digest = crypto.digest("username", "YANLIANG88")
    await db.commit()
    result = await engine.correlate_case(db, case_id)
    assert result.merged == 0
    assert (await db.get(Entity, b_id)).merged_into_id is None


async def test_cross_type_merge_is_refused(client, db):
    csrf, case = await _case_via_http(client, db)
    a = add(db, case, "username", "yanliang")
    b = add(db, case, "email", "yanliang@example.com")
    await db.commit()
    r = await client.post(
        f"/cases/{case.id}/entities/{a.id}/merge", data={"other_id": str(b.id)}, headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 400


async def test_suggestions_can_be_accepted_or_dismissed(client, db):
    csrf, case = await _case_via_http(client, db)
    add(db, case, "name", "Jon Smith")
    add(db, case, "name", "John Smith")
    add(db, case, "username", "j.doe")
    add(db, case, "username", "j_doe")
    await db.commit()
    case_id = case.id
    r = await client.post(f"/cases/{case_id}/correlate", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    panel = await client.get(f"/cases/{case_id}/suggestions")
    assert "2 to review" in panel.text and "pass 2 unavailable" in panel.text

    db.expire_all()
    names, handles = sorted(await relations(db, case_id, engine.POSSIBLE_SAME), key=lambda r: r.confidence)
    names_id, handles_id = names.id, handles.id
    r = await client.post(f"/cases/{case_id}/suggestions/{names_id}/accept", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    r = await client.post(f"/cases/{case_id}/suggestions/{handles_id}/dismiss", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200

    db.expire_all()
    assert len(await relations(db, case_id, engine.POSSIBLE_SAME)) == 0
    assert len(await relations(db, case_id, engine.NOT_SAME)) == 1
    # Dismissed pairs are not suggested again.
    await engine.correlate_case(db, case_id)
    assert len(await relations(db, case_id, engine.POSSIBLE_SAME)) == 0
    assert "0 to review" not in (await client.get(f"/cases/{case_id}/suggestions")).text


async def test_confirming_rescores_to_certainty(client, db):
    csrf, case = await _case_via_http(client, db)
    e = add(db, case, "account", "https://github.com/x", prior=0.3)
    await db.commit()
    case_id, e_id = case.id, e.id
    r = await client.post(f"/cases/{case_id}/entities/{e_id}/confirm", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200
    db.expire_all()
    assert (await db.get(Entity, e_id)).confidence == 1.0


async def test_explanations_are_encrypted_at_rest(db):
    from sqlalchemy import text

    case = await new_case(db)
    add(db, case, "name", "Jon Smith")
    add(db, case, "name", "John Smith")
    await db.flush()
    await engine.correlate_case(db, case.id)
    raw = (
        await db.execute(text("SELECT match_explanation FROM relations WHERE case_id = :c"), {"c": case.id})
    ).scalars()
    assert all(v.startswith("enc:v1:") and "Smith" not in v for v in raw)
