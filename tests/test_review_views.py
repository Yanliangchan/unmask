"""Default "best findings" view, "Not them" with undo, and the case summary."""

import json
import uuid

from sqlalchemy import select, update

from app import jobs
from app.models import Entity
from tests.conftest import case_form_data, login


async def _case_with_accounts(client, db) -> tuple[uuid.UUID, str, dict[str, Entity]]:
    csrf = await login(client)
    r = await client.post(
        "/cases", data=case_form_data(csrf, name=f"R {uuid.uuid4().hex[:6]}", target_value="janedoe", tools=["fake_ok"])
    )
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    accounts = {
        e.attributes["site"]: e
        for e in (await db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "account"))).all()
    }
    return case_id, csrf, accounts


async def _set(db, entity: Entity, **values) -> None:
    await db.execute(update(Entity).where(Entity.id == entity.id).values(**values))
    await db.commit()


async def test_best_view_hides_unchecked_and_weak_findings_and_says_so(client, db):
    case_id, _, acc = await _case_with_accounts(client, db)
    await _set(db, acc["alpha"], verification="unverified")
    await _set(db, acc["beta"], verification="verified", confidence=0.8)

    best = (await client.get(f"/cases/{case_id}/entities")).text
    assert "beta.example" in best and "alpha.example" not in best
    assert "1 more hidden (1 with a profile page that couldn't be checked)" in best
    assert 'data-show="all"' in best and "Page checked" in best and "Likely" in best

    everything = (await client.get(f"/cases/{case_id}/entities?show=all")).text
    assert "alpha.example" in everything and "Not checked" in everything


async def test_not_them_hides_everywhere_and_can_be_undone(client, db):
    case_id, csrf, acc = await _case_with_accounts(client, db)
    target = acc["alpha"]
    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}

    r = await client.post(f"/cases/{case_id}/entities/{target.id}/dismiss", headers=headers)
    trigger = json.loads(r.headers["HX-Trigger"])
    assert trigger["toast"]["undo"] == f"/cases/{case_id}/entities/{target.id}/restore"

    assert "alpha.example" not in (await client.get(f"/cases/{case_id}/entities?show=all")).text
    dismissed = (await client.get(f"/cases/{case_id}/entities?show=dismissed")).text
    assert "alpha.example" in dismissed and "Restore" in dismissed
    graph = (await client.get(f"/cases/{case_id}/graph.json")).json()
    assert str(target.id) not in {n["id"] for n in graph["nodes"]}

    await client.post(trigger["toast"]["undo"], headers=headers)
    assert "alpha.example" in (await client.get(f"/cases/{case_id}/entities?show=all")).text


async def test_targets_cannot_be_ruled_out(client, db):
    case_id, csrf, _ = await _case_with_accounts(client, db)
    seed = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.is_seed.is_(True)))
    r = await client.post(
        f"/cases/{case_id}/entities/{seed.id}/dismiss", headers={"HX-Request": "true", "X-CSRF-Token": csrf}
    )
    assert r.status_code == 400


async def test_summary_leads_with_the_likely_profiles(client, db):
    case_id, _, acc = await _case_with_accounts(client, db)
    empty = (await client.get(f"/cases/{case_id}/summary")).text
    assert "No strong matches yet" in empty or "Nothing convincing found" in empty

    await _set(
        db,
        acc["beta"],
        verification="verified",
        confidence=0.82,
        attributes={
            "site": "beta",
            "url": "https://beta.example/janedoe",
            "username": "janedoe",
            "preview": {"title": "Jane Doe", "description": "Logistics lead"},
        },
    )
    s = (await client.get(f"/cases/{case_id}/summary")).text
    assert "Likely the same person on 1 site" in s
    assert "Jane Doe" in s and "Logistics lead" in s and "Open profile" in s
    assert "None confirmed yet" in s


async def test_merge_offers_undo_by_splitting(client, db):
    case_id, csrf, acc = await _case_with_accounts(client, db)
    ids = [acc["alpha"].id, acc["beta"].id]
    r = await client.post(
        f"/cases/{case_id}/entities/{acc['alpha'].id}/merge",
        data={"other_id": str(acc["beta"].id)},
        headers={"HX-Request": "true", "X-CSRF-Token": csrf},
    )
    assert r.status_code == 200
    undo = json.loads(r.headers["HX-Trigger"])["toast"]["undo"]
    assert undo.endswith("/split")
    assert (await client.post(undo, headers={"HX-Request": "true", "X-CSRF-Token": csrf})).status_code == 200
    db.expire_all()
    rows = (await db.scalars(select(Entity).where(Entity.id.in_(ids)))).all()
    assert all(e.merged_into_id is None for e in rows)
