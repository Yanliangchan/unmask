"""What changed since a person last looked at a case: the visit record, the strip, the filters."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from app import crypto, jobs
from app.models import Entity, User
from app.services.visits import VISIT_GAP, record_visit
from tests.conftest import case_form_data, login


async def _case(client):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"V {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    return case_id, csrf


async def test_a_visit_spans_tab_changes_and_starts_again_after_a_gap(client, db):
    case_id, _ = await _case(client)
    user = await db.scalar(select(User).where(User.email == "admin@example.com"))
    t0 = datetime(2026, 10, 1, 9, 0, tzinfo=UTC)
    assert await record_visit(user, case_id, now=t0) is None  # first look
    assert await record_visit(user, case_id, now=t0 + timedelta(minutes=5)) is None  # same visit, other tab
    later = t0 + timedelta(minutes=5) + VISIT_GAP + timedelta(minutes=1)
    assert await record_visit(user, case_id, now=later) == t0 + timedelta(minutes=5)  # a new visit
    assert await record_visit(user, case_id, now=later + timedelta(minutes=2)) == t0 + timedelta(minutes=5)


async def test_the_case_says_what_is_new_since_the_last_visit(client, db):
    case_id, _ = await _case(client)
    first = (await client.get(f"/cases/{case_id}")).text
    assert "Since you last looked" not in first

    # Pretend the last visit was an hour ago, then a new finding turned up.
    user = await db.scalar(select(User).where(User.email == "admin@example.com"))
    hour_ago = datetime.now(UTC) - timedelta(hours=1)
    prefs = dict(user.preferences or {})
    prefs["visits"] = {str(case_id): {"last": hour_ago.isoformat(), "prev": None}}
    await db.execute(update(User).where(User.id == user.id).values(preferences=prefs))
    await db.execute(update(Entity).where(Entity.case_id == case_id).values(first_seen=hour_ago - timedelta(hours=1)))
    db.add(Entity(case_id=case_id, type="email", value="new@corp.example", attributes={}, source_tool="analyst",
                  value_digest=crypto.digest("email", "new@corp.example"), confidence=0.6))  # fmt: skip
    await db.commit()

    page = (await client.get(f"/cases/{case_id}")).text
    assert "Since you last looked" in page and "1 new finding" in page
    assert f"/cases/{case_id}?show=all&amp;since=" in page
    # Moving to another tab in the same visit keeps the strip.
    assert "1 new finding" in (await client.get(f"/cases/{case_id}/graph")).text

    since = hour_ago.isoformat()
    filtered = (await client.get(f"/cases/{case_id}/entities", params={"show": "all", "since": since})).text
    assert "new@corp.example" in filtered and "janedoe" not in filtered.split("<tbody", 1)[-1]
    workspace = (await client.get(f"/cases/{case_id}", params={"show": "all", "since": since})).text
    assert 'name="since"' in workspace and "New since" in workspace
    graph = (await client.get(f"/cases/{case_id}/graph", params={"since": since})).text
    assert 'data-since="' in graph
    # A malformed or naive timestamp is ignored or read as UTC, never an error.
    assert (await client.get(f"/cases/{case_id}/entities", params={"since": "yesterday"})).status_code == 200
    assert (await client.get(f"/cases/{case_id}/entities", params={"since": "2026-01-01T00:00"})).status_code == 200


async def test_graph_json_lists_scans_for_replay(client, db):
    case_id, csrf = await _case(client)
    data = (await client.get(f"/cases/{case_id}/graph.json")).json()
    assert [s["number"] for s in data["scans"]] == [1] and data["scans"][0]["at"]
