"""Provenance: every sighting records what it was searched from, what it reported and where."""

import uuid

from sqlalchemy import select, text

from app import jobs
from app.models import Entity, EntityObservation, Relation
from tests.conftest import case_form_data, login


async def _case(client, csrf):
    r = await client.post("/cases", data=case_form_data(csrf, name=f"P {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    await jobs.wait_for_all()
    return uuid.UUID(r.headers["location"].rsplit("/", 1)[1])


async def test_each_sighting_records_its_source_and_the_step_before_it(client, db):
    csrf = await login(client)
    case_id = await _case(client, csrf)
    seed = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.is_seed.is_(True)))
    account = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.type == "account").limit(1))
    obs = await db.scalar(select(EntityObservation).where(EntityObservation.entity_id == account.id))
    assert obs.parent_entity_id == seed.id and obs.reliability == "C"
    assert obs.source_url == account.attributes["url"] and obs.reported["site"] in ("alpha", "beta")
    assert obs.reported["_why"].startswith("registered on")
    # Stored encrypted, like every other case value.
    raw = (await db.execute(text("SELECT source_url FROM entity_observations WHERE id = :i"), {"i": obs.id})).scalar()
    assert raw and account.attributes["url"] not in raw
    page = (await client.get(f"/cases/{case_id}/entities/{account.id}")).text
    assert "Provenance" in page and "searched from" in page and "janedoe" in page and "(target)" in page

    # Seen again by a rescan: the link's history grows, no duplicate row.
    await client.post(f"/cases/{case_id}/scans", data={"csrf_token": csrf})
    await jobs.wait_for_all()
    rels = (await db.scalars(select(Relation).where(Relation.entity_b_id == account.id,
                                                     Relation.relation_type == "has_account"))).all()  # fmt: skip
    for r in rels:
        await db.refresh(r)
    assert len(rels) == 1 and rels[0].seen_count == 2 and rels[0].basis == "observed" and rels[0].directed


async def test_a_finding_added_by_hand_says_who_added_it(client, db):
    csrf = await login(client)
    case_id = await _case(client, csrf)
    r = await client.post(f"/cases/{case_id}/findings",
                          data={"csrf_token": csrf, "type": "web_mention", "value": "https://news.example/a",
                                "note": "found in a press release"})  # fmt: skip
    assert r.status_code == 303
    e = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.type == "web_mention"))
    obs = await db.scalar(select(EntityObservation).where(EntityObservation.entity_id == e.id))
    assert obs.source_tool == "analyst" and obs.scan_run_id is None
    assert obs.reported["note"] == "found in a press release"
    page = (await client.get(f"/cases/{case_id}/entities/{e.id}")).text
    assert "added by hand" in page
