"""The case workspace: evidence drawer, notes and mentions, bulk decisions, saved views, timeline track."""

import json
import uuid

from sqlalchemy import select, update

from app import jobs
from app.models import Entity, Notification, SavedView, User
from app.security import hash_password
from tests.conftest import case_form_data, login


async def _case(client, db, **overrides):
    csrf = await login(client)
    data = case_form_data(csrf, name=f"W {uuid.uuid4().hex[:6]}", tools=["fake_ok"], **overrides)
    r = await client.post("/cases", data=data)
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    accounts = {
        e.attributes["site"]: e
        for e in (await db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "account"))).all()
    }
    await db.execute(update(Entity).where(Entity.id.in_([e.id for e in accounts.values()])).values(confidence=0.8))
    await db.commit()
    return case_id, csrf, accounts


async def test_rows_open_the_drawer_with_evidence_and_actions(client, db):
    case_id, csrf, acc = await _case(client, db)
    table = (await client.get(f"/cases/{case_id}/entities?show=all")).text
    alpha = acc["alpha"]
    assert f'data-drawer="/cases/{case_id}/entities/{alpha.id}/drawer"' in table
    assert f'class="row-select" value="{alpha.id}"' in table and "data-select-all" in table
    drawer = await client.get(f"/cases/{case_id}/entities/{alpha.id}/drawer")
    assert drawer.status_code == 200
    assert 'id="drawer-title"' in drawer.text and "Same person" in drawer.text and "Add note" in drawer.text
    assert (await client.get(f"/cases/{case_id}/entities/{uuid.uuid4()}/drawer")).status_code == 404


async def test_notes_escape_html_and_notify_only_case_members(client, db):
    email = f"member-{uuid.uuid4().hex[:6]}@example.com"
    db.add(User(email=email, password_hash=hash_password("member-password-1")))
    await db.commit()
    case_id, csrf, acc = await _case(client, db)
    await client.post(f"/cases/{case_id}/settings/share", data={"csrf_token": csrf, "email": email})
    member = await db.scalar(select(User).where(User.email == email))

    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}
    body = f"Same avatar as the target. @{email} can you check? @stranger@nowhere.example <b>x</b>"
    r = await client.post(f"/cases/{case_id}/entities/{acc['alpha'].id}/notes", data={"body": body}, headers=headers)
    assert r.status_code == 200
    assert f'<span class="mention">@{email}</span>' in r.text
    assert "&lt;b&gt;x&lt;/b&gt;" in r.text and "<b>x</b>" not in r.text
    notes = (
        await db.scalars(select(Notification).where(Notification.case_id == case_id, Notification.kind == "mention"))
    ).all()
    assert [n.user_id for n in notes] == [member.id] and notes[0].kind == "mention"
    url = f"/cases/{case_id}/entities/{acc['alpha'].id}/notes"
    empty = await client.post(url, data={"body": "  "}, headers=headers)
    assert empty.status_code == 400


async def test_bulk_decisions_apply_to_the_selection_and_undo(client, db):
    case_id, csrf, acc = await _case(client, db)
    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}
    pair = [acc["alpha"].id, acc["beta"].id]
    ids = ",".join(map(str, pair))
    bulk = f"/cases/{case_id}/entities/bulk"
    r = await client.post(bulk, data={"action": "dismiss", "reason": "bot_or_spam", "ids": ids}, headers=headers)
    trigger = json.loads(r.headers["HX-Trigger"])
    assert trigger["entities-changed"] and trigger["toast"]["message"] == "Marked not them: 2 findings"
    db.expire_all()
    rows = (await db.scalars(select(Entity).where(Entity.id.in_(pair)))).all()
    assert all(e.dismissed_flag and e.dismiss_reason == "bot_or_spam" for e in rows)

    await client.post(trigger["toast"]["undo"], headers=headers)
    db.expire_all()
    rows = (await db.scalars(select(Entity).where(Entity.id.in_(pair)))).all()
    assert not any(e.dismissed_flag for e in rows)

    seed = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.is_seed.is_(True)))
    r = await client.post(bulk, data={"action": "dismiss", "ids": str(seed.id)}, headers=headers)
    assert "0 findings" in json.loads(r.headers["HX-Trigger"])["toast"]["message"]  # targets are never bulk-dismissed
    bad = await client.post(bulk, data={"action": "delete", "ids": ids}, headers=headers)
    assert bad.status_code == 400


async def test_saved_views_are_per_user_and_keep_only_known_filters(client, db):
    case_id, csrf, _ = await _case(client, db)
    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}
    r = await client.post(
        f"/cases/{case_id}/views",
        data={"name": "Accounts", "type": "account", "show": "nonsense", "evil": "1"},
        headers=headers,
    )
    assert r.status_code == 200 and "Accounts" in r.text and "Undecided" in r.text
    view = await db.scalar(select(SavedView).where(SavedView.case_id == case_id))
    assert view.params == {"type": "account"}
    page = (await client.get(f"/cases/{case_id}")).text
    assert "Saved by you" in page and 'data-view=\'{"type": "account"}\'' in page
    # Undecided hides confirmed findings.
    undecided = (await client.get(f"/cases/{case_id}/entities?show=undecided")).text
    assert "alpha.example" in undecided
    r = await client.post(f"/cases/{case_id}/views/{view.id}/delete", headers=headers)
    assert "Saved by you" not in r.text


async def test_timeline_track_places_scans_and_counts_new_findings(client, db):
    case_id, csrf, _ = await _case(client, db)
    await client.post(f"/cases/{case_id}/scans", data={"csrf_token": csrf})
    await jobs.wait_for_all()
    page = (await client.get(f"/cases/{case_id}/timeline")).text
    assert "Scans over time" in page and 'aria-label="Scan 1,' in page and 'aria-label="Scan 2,' in page
    assert ": 0 new," in page  # the rescan found nothing new
