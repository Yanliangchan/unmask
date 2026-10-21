"""The case working log: entries, pins, and drafting the assessment from them."""

import json
import uuid

from sqlalchemy import select, text

from app import jobs
from app.models import AccessLog, Entity, Note, Relation
from tests.conftest import case_form_data, login


async def _case(client, csrf=None):
    csrf = csrf or await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"Log {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    return case_id, csrf


async def test_entries_and_pins_make_a_log_and_a_draft(client, db):
    case_id, csrf = await _case(client)
    assert "Log</a>" in (await client.get(f"/cases/{case_id}")).text  # the tab is there
    page = (await client.get(f"/cases/{case_id}/log")).text
    assert "No entries yet" in page and "Draft the assessment" not in page

    r = await client.post(f"/cases/{case_id}/log", data={"csrf_token": csrf, "body": "Checked alpha: bio matches."})
    assert r.status_code == 303 and "#entry-" in r.headers["location"]
    entity = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.type == "account").limit(1))
    rel = await db.scalar(select(Relation).where(Relation.case_id == case_id).limit(1))
    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}
    pinned = await client.post(f"/cases/{case_id}/entities/{entity.id}/pin", headers=headers, data={"why": "same bio"})
    assert json.loads(pinned.headers["HX-Trigger"])["toast"]["message"] == "Pinned to the working log."
    again = await client.post(f"/cases/{case_id}/entities/{entity.id}/pin", headers=headers)
    assert "Already pinned" in again.headers["HX-Trigger"]
    await client.post(f"/cases/{case_id}/links/{rel.id}/pin", headers=headers)

    page = (await client.get(f"/cases/{case_id}/log")).text
    assert "Checked alpha: bio matches." in page and entity.value in page and "same bio" in page
    assert 'Pinned <span class="count">2</span>' in page

    # Stored encrypted, like any note.
    raw = (
        await db.execute(text("SELECT body FROM notes WHERE case_id = :c AND kind = 'log'"), {"c": case_id})
    ).scalar()
    assert "bio matches" not in raw

    # Log entries and pins never show up as notes on the finding itself.
    drawer = (await client.get(f"/cases/{case_id}/entities/{entity.id}/drawer")).text
    assert "same bio" not in drawer and "Pin to log" in drawer

    settings = (await client.get(f"/cases/{case_id}/settings?draft=log")).text
    assert "Drafted from the working log" in settings and "Key findings:" in settings
    assert f"{entity.value} (score" in settings and "same bio" in settings and "Checked alpha: bio matches." in settings
    assert "Conclusion: [what the evidence supports" in settings
    db.expire_all()
    from app.models import Investigation

    assert (await db.get(Investigation, case_id)).analyst_assessment is None  # a draft is never saved for you

    actions = set((await db.scalars(select(AccessLog.action).where(AccessLog.case_id == case_id))).all())
    assert {"log_entry", "pin"} <= actions
    activity = (await client.get(f"/cases/{case_id}/activity")).text
    assert "wrote in the working log" in activity and "pinned to the working log" in activity


async def test_only_the_author_or_owner_removes_entries(client, db):
    case_id, csrf = await _case(client)
    await client.post(f"/cases/{case_id}/log", data={"csrf_token": csrf, "body": "first"})
    note_id = await db.scalar(select(Note.id).where(Note.case_id == case_id, Note.kind == "log"))
    r = await client.post(f"/cases/{case_id}/log/{note_id}/delete", data={"csrf_token": csrf})
    assert r.status_code == 303
    db.expire_all()
    assert await db.scalar(select(Note).where(Note.id == note_id)) is None
    other = await client.post(f"/cases/{case_id}/log/{uuid.uuid4()}/delete", data={"csrf_token": csrf})
    assert other.status_code == 404


async def test_a_pin_must_point_at_exactly_one_thing(db, client):
    import pytest
    from sqlalchemy.exc import IntegrityError

    case_id, _ = await _case(client)
    db.add(Note(case_id=case_id, kind="pin", body=""))
    with pytest.raises(IntegrityError):
        await db.flush()
    await db.rollback()


async def test_pins_from_another_case_are_refused(client, db):
    case_a, csrf = await _case(client)
    case_b, _ = await _case(client, csrf)
    entity = await db.scalar(select(Entity).where(Entity.case_id == case_b).limit(1))
    r = await client.post(f"/cases/{case_a}/entities/{entity.id}/pin", data={"csrf_token": csrf})
    assert r.status_code == 404
