"""Pivot rule engine: chains, dedupe, limits and the Pivot Log."""

import uuid

import pytest
from sqlalchemy import select

from app import jobs
from app.adapters import registry
from app.config import get_settings
from app.models import AccessLog, Entity, PivotLog, Relation, ScanRun
from app.pivots import rules
from app.pivots.rules import PivotRule, email_domain, guessed_emails, same_value
from app.services.tools import sync_tool_config
from tests.conftest import case_form_data, login
from tests.fakes import FakeDomainAdapter, FakeEmailAdapter

TEST_RULES = [
    PivotRule("username-guess", "username found (conf > 0.6) → guessed emails", "username", 0.6, "fake_email",
              guessed_emails),
    # Same tool the direct scan already ran on the target: must never re-run.
    PivotRule("username-again", "username found (conf > 0.6)", "username", 0.6, "fake_ok", same_value("username")),
    PivotRule("email-domain", "email found (conf > 0.4) → its domain", "email", 0.4, "fake_domain", email_domain),
]  # fmt: skip


@pytest.fixture
async def pivot_env(db, monkeypatch):
    registry.register(FakeEmailAdapter())
    registry.register(FakeDomainAdapter())
    await sync_tool_config(db)
    monkeypatch.setattr(rules, "RULES", TEST_RULES)
    monkeypatch.setattr(rules, "RULES_BY_ID", {r.id: r for r in TEST_RULES})
    settings = get_settings()
    monkeypatch.setattr(settings, "pivot_email_providers", "gmail.com,acme-corp.example")
    monkeypatch.setattr(settings, "pivot_max_depth", 2)
    monkeypatch.setattr(settings, "pivot_budget", 20)
    yield settings
    registry.unregister("fake_email")
    registry.unregister("fake_domain")


async def start_case(client, csrf, **overrides) -> uuid.UUID:
    data = case_form_data(
        csrf,
        name=f"Pivot {uuid.uuid4().hex[:6]}",
        target_value="janedoe",
        tools=["fake_ok", "fake_email", "fake_domain"],
    )
    data.update(overrides)
    r = await client.post("/cases", data=data)
    assert r.status_code == 303, r.text
    await jobs.wait_for_all()
    return uuid.UUID(r.headers["location"].rsplit("/", 1)[1])


async def rows_for(db, case_id):
    db.expire_all()
    return list(
        (await db.scalars(select(PivotLog).where(PivotLog.case_id == case_id).order_by(PivotLog.created_at))).all()
    )


async def runs_for(db, case_id):
    return list(
        (await db.scalars(select(ScanRun).where(ScanRun.case_id == case_id).order_by(ScanRun.run_number))).all()
    )


async def test_pivot_chain_runs_and_is_logged(pivot_env, client, db):
    csrf = await login(client)
    case_id = await start_case(client, csrf)

    runs = await runs_for(db, case_id)
    assert [(r.run_number, r.triggered_by, r.status) for r in runs] == [
        (1, "manual", "completed"),
        (2, "pivot_chain", "completed"),  # username → guessed emails → fake_email
        (3, "pivot_chain", "completed"),  # confirmed guessed email → its domain → fake_domain
    ]
    run_ids = [r.id for r in runs]
    rows = await rows_for(db, case_id)
    assert [(r.triggered_tool, r.rule_matched.split(":")[0]) for r in rows] == [
        ("fake_email", "username-guess"),
        ("fake_domain", "email-domain"),
    ]
    assert rows[0].scan_run_id == run_ids[1] and rows[1].scan_run_id == run_ids[2]
    assert all(r.job_id == f"scan-{r.scan_run_id}" for r in rows)
    # The fake_ok rule would re-run the target's own input: never logged, never run.
    assert not any(r.triggered_tool == "fake_ok" for r in rows)

    # Only the guessed address that is actually registered became an entity.
    emails = (await db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "email"))).all()
    assert [e.value for e in emails] == ["janedoe@acme-corp.example"]
    assert emails[0].attributes["origin"] == "guessed from username"
    seed = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.is_seed.is_(True)))
    reg = await db.scalar(
        select(Relation).where(Relation.case_id == case_id, Relation.relation_type == "registered_on")
    )
    assert reg.entity_a_id == seed.id  # pivot findings hang off the triggering entity
    hosts = (await db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "hostname"))).all()
    assert sorted(h.value for h in hosts) == ["mail.acme-corp.example", "www.acme-corp.example"]

    # The Pivot Log explains each step; the source run note links to it.
    page = await client.get(f"/cases/{case_id}/pivots")
    assert page.status_code == 200
    assert "Fake Email" in page.text and "username found (conf &gt; 0.6) → guessed emails" in page.text
    assert "janedoe@acme-corp.example" in page.text
    # Follow-ups sit under the Log section, with their count.
    assert 'Follow-ups<span class="count">2</span>' in page.text


async def test_shared_mail_domains_are_never_pivoted_onto(pivot_env, client, db):
    pivot_env.pivot_email_providers = "gmail.com"
    csrf = await login(client)
    case_id = await start_case(client, csrf, target_value="johnsmith")
    rows = await rows_for(db, case_id)
    assert [r.triggered_tool for r in rows] == ["fake_email"]
    assert len(await runs_for(db, case_id)) == 2  # no fake_domain run on gmail.com


async def test_depth_limit_is_logged_as_skipped(pivot_env, client, db):
    pivot_env.pivot_max_depth = 1
    csrf = await login(client)
    case_id = await start_case(client, csrf)
    rows = await rows_for(db, case_id)
    assert len(await runs_for(db, case_id)) == 2
    skipped = [r for r in rows if r.scan_run_id is None]
    assert len(skipped) == 1 and skipped[0].triggered_tool == "fake_domain"
    assert "skipped: pivot depth limit (1) reached" in skipped[0].rule_matched
    page = await client.get(f"/cases/{case_id}/pivots")
    assert "pivot depth limit (1) reached" in page.text


async def test_budget_is_logged_as_skipped(pivot_env, client, db):
    pivot_env.pivot_budget = 0
    csrf = await login(client)
    case_id = await start_case(client, csrf)
    rows = await rows_for(db, case_id)
    assert len(rows) == 1 and "pivot budget (0 per evaluation) reached" in rows[0].rule_matched
    assert len(await runs_for(db, case_id)) == 1


async def test_excluded_tool_is_logged_not_run(pivot_env, client, db):
    csrf = await login(client)
    # fake_email is left out of this case's tool selection.
    case_id = await start_case(client, csrf, tools=["fake_ok", "fake_domain"])
    rows = await rows_for(db, case_id)
    assert len(rows) == 1 and "Fake Email is excluded from this case" in rows[0].rule_matched
    assert len(await runs_for(db, case_id)) == 1


async def test_rescan_does_not_repeat_pivots(pivot_env, client, db):
    csrf = await login(client)
    case_id = await start_case(client, csrf)
    before = len(await rows_for(db, case_id))
    await client.post(f"/cases/{case_id}/scans", data={"csrf_token": csrf})
    await jobs.wait_for_all()
    assert len(await rows_for(db, case_id)) == before
    assert [r.triggered_by for r in await runs_for(db, case_id)][-1] == "manual"


async def test_auto_pivot_switch(pivot_env, client, db):
    csrf = await login(client)
    case_id = await start_case(client, csrf, target_value="nopivots")
    rows_before = len(await rows_for(db, case_id))
    r = await client.post(f"/cases/{case_id}/auto-pivot", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and "checked" not in r.text
    # New findings after switching off start nothing.
    db.expire_all()
    await client.post(f"/cases/{case_id}/scans", data={"csrf_token": csrf})
    await jobs.wait_for_all()
    assert len(await rows_for(db, case_id)) == rows_before
    last = (await runs_for(db, case_id))[-1]
    assert last.failure_details["_pivots"] == "automatic pivoting is off for this case"
    actions = set((await db.scalars(select(AccessLog.action).where(AccessLog.case_id == case_id))).all())
    assert "auto_pivot_off" in actions


async def test_a_skipped_pivot_can_be_retried_by_the_analyst(pivot_env, client, db):
    pivot_env.pivot_max_depth = 1
    csrf = await login(client)
    case_id = await start_case(client, csrf)
    skipped = [r.id for r in await rows_for(db, case_id) if r.scan_run_id is None]
    assert len(skipped) == 1
    page = (await client.get(f"/cases/{case_id}/pivots")).text
    assert "Retry all skipped" in page and f"/pivots/{skipped[0]}/retry" in page

    r = await client.post(f"/cases/{case_id}/pivots/{skipped[0]}/retry", data={"csrf_token": csrf})
    assert r.status_code == 303 and "retried=1" in r.headers["location"]
    await jobs.wait_for_all()
    db.expire_all()
    row = await db.get(PivotLog, skipped[0])
    assert row.scan_run_id is not None and "retried by analyst (pivot depth limit (1) reached)" in row.rule_matched
    runs = await runs_for(db, case_id)
    assert runs[-1].triggered_by == "pivot_chain" and runs[-1].tools_included == ["fake_domain"]
    assert any(a == "retry_pivots" for a in (await db.scalars(select(AccessLog.action))).all())
    hosts = (await db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "hostname"))).all()
    assert hosts  # the retried pivot really ran
    assert "retried by you" in (await client.get(f"/cases/{case_id}/pivots")).text

    # Nothing left to retry: a second attempt on the same row is a 404, not a second run.
    again = await client.post(f"/cases/{case_id}/pivots/{skipped[0]}/retry", data={"csrf_token": csrf})
    assert again.status_code == 404


async def test_a_retry_still_refuses_a_tool_that_cannot_run(pivot_env, client, db):
    csrf = await login(client)
    case_id = await start_case(client, csrf, tools=["fake_ok", "fake_domain"])
    r = await client.post(f"/cases/{case_id}/pivots/retry-skipped", data={"csrf_token": csrf})
    assert "retried=0" in r.headers["location"] and "refused=1" in r.headers["location"]
    assert len(await runs_for(db, case_id)) == 1
    page = (await client.get(r.headers["location"])).text
    assert "Nothing could be retried" in page


def test_pivots_are_ranked_by_expected_value():
    from app.pivots.engine import expected_value
    from app.pivots.rules import PivotInput

    real, guess = [PivotInput("email", "a@b.example")], [PivotInput("email", "a@gmail.com", guessed=True)]
    assert expected_value(0.9, 0.5, real) == 0.45
    assert expected_value(0.9, 0.5, guess) == 0.225  # guesses are worth half
    assert expected_value(0.7, 0.9, real) > expected_value(0.9, 0.5, real)  # a tool that usually finds wins


async def test_tool_yield_learns_from_pivots_that_found_something(pivot_env, client, db):
    from app.pivots.engine import tool_yields

    csrf = await login(client)
    case_id = await start_case(client, csrf)
    yields = await tool_yields(db)
    assert yields["fake_email"] > 0.5 and yields["fake_domain"] > 0.5
    rows = await rows_for(db, case_id)
    assert all(" — value " in r.rule_matched for r in rows)
