"""The one-at-a-time review queue."""

import json
import uuid

from sqlalchemy import select, update

from app import jobs
from app.models import Entity
from tests.conftest import case_form_data, login


async def _case(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"Q {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    accounts = {
        e.attributes["site"]: e
        for e in (await db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "account"))).all()
    }
    # Make both visible in the default view, alpha the stronger one.
    for site, conf in (("alpha", 0.8), ("beta", 0.5)):
        await db.execute(update(Entity).where(Entity.id == accounts[site].id).values(confidence=conf))
    await db.commit()
    return case_id, csrf, accounts


async def test_queue_shows_the_strongest_undecided_finding_next_to_the_subject(client, db):
    case_id, csrf, acc = await _case(client, db)
    page = await client.get(f"/cases/{case_id}/review")
    assert page.status_code == 200 and "<kbd>Y</kbd>" in page.text

    card = (await client.get(f"/cases/{case_id}/review/next")).text
    assert "alpha.example" in card and "2</strong> left to review" in card
    assert "The subject" in card and "janedoe" in card and "london" in card
    # Skipping moves on without deciding.
    card = (await client.get(f"/cases/{case_id}/review/next?skip={acc['alpha'].id}")).text
    assert "beta.example" in card and "1 skipped" in card


async def test_answers_leave_the_queue_and_confirm_offers_undo(client, db):
    case_id, csrf, acc = await _case(client, db)
    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}
    r = await client.post(f"/cases/{case_id}/entities/{acc['alpha'].id}/confirm?toast=1", headers=headers)
    toast = json.loads(r.headers["HX-Trigger"])["toast"]
    assert toast["message"].startswith("Confirmed") and toast["undo"].endswith("/confirm")
    await client.post(
        f"/cases/{case_id}/entities/{acc['beta'].id}/dismiss", data={"reason": "bot_or_spam"}, headers=headers
    )
    done = (await client.get(f"/cases/{case_id}/review/next")).text
    assert "All reviewed" in done
    # The summary points at the queue while there's something to decide.
    await client.post(toast["undo"], headers=headers)
    summary = (await client.get(f"/cases/{case_id}/summary")).text
    assert f"/cases/{case_id}/review" in summary and "Review 1 finding" in summary
