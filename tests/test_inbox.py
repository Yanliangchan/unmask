"""Home inbox, getting started and the sample case, templates, notifications and the activity feed."""

import json
import uuid

import httpx
from sqlalchemy import select

from app import jobs
from app.config import get_settings
from app.models import Investigation, Notification, User
from app.security import hash_password
from app.services import notifications
from tests.conftest import case_form_data, login


async def _fresh_user(client, db):
    email = f"analyst-{uuid.uuid4().hex[:8]}@example.com"
    db.add(User(email=email, password_hash=hash_password("analyst-password-1")))
    await db.commit()
    csrf = await login(client, email, "analyst-password-1")
    return email, csrf


async def test_new_user_home_has_the_checklist_and_a_sample_case(client, db):
    email, csrf = await _fresh_user(client, db)
    home = (await client.get("/")).text
    assert "Getting started" in home and "0 of 5 done" in home and "Explore a sample case" in home

    r = await client.post("/onboarding/sample", data={"csrf_token": csrf})
    case_url = r.headers["location"]
    page = (await client.get(case_url)).text
    assert "This is a sample case" in page and "data-run-scan" not in page
    table = (await client.get(case_url + "/entities?show=all")).text
    assert "code.example/alexrivera" in table and "Alex Rivera" in table
    # Opening it again doesn't make another one, and it can't be scanned or watched.
    assert (await client.post("/onboarding/sample", data={"csrf_token": csrf})).headers["location"] == case_url
    assert (await client.post(case_url + "/scans", data={"csrf_token": csrf})).status_code == 400
    assert (await client.post(case_url + "/watch", data={"csrf_token": csrf})).status_code == 400

    home = (await client.get("/")).text
    assert "Open the sample case" in home and "0 of 5 done" in home  # the sample doesn't count as your first case
    assert "to review" in home  # its undecided findings show under Needs you
    await client.post("/onboarding/dismiss", data={"csrf_token": csrf})
    assert "Getting started" not in (await client.get("/")).text
    await client.post("/account/checklist", data={"csrf_token": csrf})
    assert "Getting started" in (await client.get("/")).text


async def test_templates_prefill_the_form_and_turn_on_watch_mode(client, db):
    csrf = await login(client)
    page = (await client.get("/cases/new?template=domain_footprint")).text
    assert 'name="template" value="domain_footprint"' in page and "Attack surface" in page
    assert '<option value="domain" selected>' in page
    unknown = (await client.get("/cases/new?template=nope")).text
    assert 'name="template"' not in unknown and "Blank case" in unknown

    data = case_form_data(csrf, name=f"T {uuid.uuid4().hex[:6]}", target_value="acme.example", target_type="domain",
                          tools=["fake_ok"], template="domain_footprint")  # fmt: skip
    r = await client.post("/cases", data=data)
    await jobs.wait_for_all()
    case = await db.get(Investigation, uuid.UUID(r.headers["location"].rsplit("/", 1)[1]))
    assert case.template == "domain_footprint"
    assert case.watch_config["enabled"] and case.watch_config["frequency"] == "weekly"
    activity = (await client.get(f"/cases/{case.id}/activity")).text
    assert "created the case from the Domain footprint template" in activity


async def test_scan_notifications_in_app_and_outside_without_case_details(client, db, monkeypatch):
    email, csrf = await _fresh_user(client, db)
    sent: list[httpx.Request] = []
    notifications.transport = httpx.MockTransport(lambda req: sent.append(req) or httpx.Response(200))
    notifications.sent_mail = []
    s = get_settings()
    monkeypatch.setattr(s, "smtp_host", "smtp.example.com")
    monkeypatch.setattr(s, "smtp_from", "unmask@example.com")
    try:
        bad = await client.post("/account/notifications", data={
            "csrf_token": csrf, "slack_webhook": "https://169.254.169.254/latest", "slack": "on"})  # fmt: skip
        assert bad.status_code == 422 and "Slack incoming-webhook" in bad.text
        ok = await client.post("/account/notifications", data={
            "csrf_token": csrf, "slack_webhook": "https://hooks.slack.com/services/T0/B0/xyz", "slack": "on",
            "email": "on", "kinds": ["scan_finished", "mention"]})  # fmt: skip
        assert ok.headers["location"] == "/account?saved=saved"
        user = await db.scalar(select(User).where(User.email == email))
        await db.refresh(user)
        assert user.slack_webhook.endswith("/xyz") and "xyz" not in (await client.get("/account")).text

        secret_name = f"Secret subject {uuid.uuid4().hex[:6]}"
        r = await client.post("/cases", data=case_form_data(csrf, name=secret_name, tools=["fake_ok"]))
        case_id = r.headers["location"].rsplit("/", 1)[1]
        await jobs.wait_for_all()
        await notifications.drain()

        note = await db.scalar(select(Notification).where(Notification.user_id == user.id))
        assert note.kind == "scan_finished" and secret_name in note.text and "new finding" in note.text
        assert (
            '<span class="nav-badge" aria-label="1 unread notification">1</span>'
            in (await client.get("/notifications/badge")).text
        )
        page = (await client.get("/notifications")).text
        assert secret_name in page and "(new)" in page
        assert (await client.get("/notifications/badge")).text == ""  # reading the list marks them read

        assert len(sent) == 1 and str(sent[0].url) == "https://hooks.slack.com/services/T0/B0/xyz"
        body = json.loads(sent[0].content)
        assert body["text"].startswith("A scan finished.") and f"/cases/{case_id}" in body["text"]
        assert secret_name not in body["text"] and "janedoe" not in body["text"]
        mail = notifications.sent_mail[0]
        assert mail["To"] == email and secret_name not in mail.as_string() and "janedoe" not in mail.as_string()
    finally:
        notifications.transport = None
        notifications.sent_mail = None


async def test_activity_feed_shows_decisions_and_notes_in_plain_words(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"A {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = r.headers["location"].rsplit("/", 1)[1]
    await jobs.wait_for_all()
    from app.models import Entity

    entity = await db.scalar(
        select(Entity).where(Entity.case_id == uuid.UUID(case_id), Entity.type == "account").limit(1)
    )
    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}
    await client.post(f"/cases/{case_id}/entities/{entity.id}/confirm?toast=1", headers=headers)
    await client.post(f"/cases/{case_id}/entities/{entity.id}/notes", data={"body": "Same avatar"}, headers=headers)
    page = (await client.get(f"/cases/{case_id}/activity")).text
    assert "admin@example.com</strong> confirmed a finding" in page and entity.value in page
    assert "added a note" in page and "Same avatar" in page
    assert "Scan 1 finished" in page and "started scan 1" in page
    assert "view_case" not in page and "opened" not in page
