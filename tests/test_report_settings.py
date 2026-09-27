"""Case Settings screen and report export."""

import uuid

from sqlalchemy import select, text

from app import crypto, jobs
from app.models import AccessLog, Entity, Investigation, User
from app.scheduler import watch_state
from app.security import hash_password
from app.services.report import find_contradictions, render_markdown
from tests.conftest import case_form_data, login

ASSESSMENT = (
    "The GitHub and GitLab accounts very likely belong to the subject: same handle, matching profile name. "
    "Nothing links the breach record to them."
)


async def make_case(client, csrf, **overrides) -> uuid.UUID:
    data = case_form_data(csrf, **{"name": f"R {uuid.uuid4().hex[:6]}", "tools": ["fake_ok", "fake_fail"], **overrides})
    r = await client.post("/cases", data=data)
    assert r.status_code == 303, r.text
    await jobs.wait_for_all()
    return uuid.UUID(r.headers["location"].rsplit("/", 1)[1])


async def save_assessment(client, csrf, case_id, text_value=ASSESSMENT):
    return await client.post(
        f"/cases/{case_id}/settings/assessment", data={"csrf_token": csrf, "analyst_assessment": text_value}
    )


# --- Export gate -------------------------------------------------------------------------


async def test_export_is_blocked_until_a_real_assessment_exists(client, db):
    csrf = await login(client)
    case_id = await make_case(client, csrf)
    for path in ("report", "report.md"):
        r = await client.get(f"/cases/{case_id}/{path}")
        assert r.status_code == 303 and r.headers["location"].endswith("error=assessment")
    page = await client.get(f"/cases/{case_id}/settings")
    assert "Write the assessment to enable export" in page.text

    await save_assessment(client, csrf, case_id, "Looks like him.")  # too short to count
    assert (await client.get(f"/cases/{case_id}/report.md")).status_code == 303


async def test_markdown_report_contents(client, db):
    # Earlier tests may have tripped fake_fail's circuit breaker; this one needs it to run (and fail).
    await db.execute(
        text("UPDATE tool_config SET enabled = true, circuit_open = false, consecutive_failures = 0 "
             "WHERE tool_name = 'fake_fail'")
    )  # fmt: skip
    await db.commit()
    csrf = await login(client)
    case_id = await make_case(client, csrf, target_tags="london")
    r = await save_assessment(client, csrf, case_id)
    assert r.status_code == 303 and r.headers["location"].endswith("saved=assessment")

    r = await client.get(f"/cases/{case_id}/report.md")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert f"unmask-case-{case_id}-" in r.headers["content-disposition"]
    md = r.text
    for heading in ("## Analyst assessment", "## Authorization", "## Targets", "### High confidence",
                    "### Low confidence", "## Contradictions between sources", "## Scan timeline",
                    "## Coverage gaps", "## Method"):  # fmt: skip
        assert heading in md, heading
    assert "The GitHub and GitLab accounts very likely belong" in md
    assert "`https://alpha.example/janedoe`" in md
    assert "- fake_fail failed in its latest run (#1)" in md  # coverage gap is surfaced
    assert "Written consent from subject" in md

    actions = set((await db.scalars(select(AccessLog.action).where(AccessLog.case_id == case_id))).all())
    assert {"analyst_assessment", "export_report"} <= actions

    html = await client.get(f"/cases/{case_id}/report")
    assert html.status_code == 200 and "Print or save as PDF" in html.text
    assert "noindex" in html.headers["x-robots-tag"]


async def test_markdown_neutralises_hostile_values(client, db):
    csrf = await login(client)
    case_id = await make_case(client, csrf)
    case = await db.get(Investigation, case_id)
    evil = "x`|y [click](http://evil) *bold*"
    db.add(Entity(case_id=case_id, type="name", value=evil, value_digest=crypto.digest("name", evil),
                  attributes={}, source_tool="fake_ok", confidence=0.5, source_reliability="C"))  # fmt: skip
    case.analyst_assessment = ASSESSMENT + " See [here](http://evil)."
    await db.commit()
    md = (await client.get(f"/cases/{case_id}/report.md")).text
    assert "`` x`\\|y [click](http://evil) *bold* ``" in md  # inside a code span, pipe escaped
    assert "\\[here\\](http://evil)" in md  # assessment text can't become a link


def test_contradictions_flag_disagreeing_profiles_only():
    def account(site, **profile):
        return Entity(id=uuid.uuid4(), type="account", value=f"https://{site}", source_tool="maigret",
                      attributes={"site": site, "profile": profile})  # fmt: skip

    active = [
        account("github.com", location="Singapore", fullname="Yan Liang Chan"),
        account("reddit.com", location="Berlin", fullname="Yan Chan"),  # compatible name, different city
        account("gitlab.com", location="singapore"),
    ]
    found = find_contradictions(active, {})
    assert [c.title for c in found] == ["Accounts disagree on location"]
    assert "Singapore" in found[0].detail and "Berlin" in found[0].detail


def test_render_markdown_handles_an_empty_case():
    from datetime import UTC, datetime

    from app.services.report import Report

    case = Investigation(id=uuid.uuid4(), name="Empty", authorization_note="note", analyst_assessment=ASSESSMENT)
    case.targets = []
    report = Report(case=case, generated_at=datetime.now(UTC), generated_by="a@example.com",
                    tiers=[("High confidence", [])], runs=[], pending_suggestions=0, contradictions=[],
                    coverage_gaps=[], pivots_run=0, pivots_skipped=0, diff_summary=None, entity_count=0)  # fmt: skip
    md = render_markdown(report)
    assert "None flagged." in md and "None: every tool's latest run completed." in md


# --- Settings forms ----------------------------------------------------------------------


async def test_watch_retention_and_pivot_settings(client, db):
    csrf = await login(client)
    case_id = await make_case(client, csrf)
    await client.post(
        f"/cases/{case_id}/settings/watch", data={"csrf_token": csrf, "enabled": "on", "frequency": "monthly"}
    )
    await client.post(f"/cases/{case_id}/settings/retention", data={"csrf_token": csrf, "retention_days": "99999"})
    await client.post(f"/cases/{case_id}/settings/pivot", data={"csrf_token": csrf})
    db.expire_all()
    case = await db.get(Investigation, case_id)
    assert watch_state(case)["enabled"] and watch_state(case)["frequency"] == "monthly"
    assert case.retention_days == 3650 and case.permanently_active is False
    assert case.watch_config["auto_pivot"] is False
    await client.post(
        f"/cases/{case_id}/settings/retention",
        data={"csrf_token": csrf, "retention_days": "30", "permanently_active": "on"},
    )
    db.expire_all()
    assert (await db.get(Investigation, case_id)).permanently_active is True
    page = await client.get(f"/cases/{case_id}/settings")
    assert "Permanently active" in page.text and "monthly" in page.text


async def test_sharing_is_owner_only_and_grants_access(client, db):
    email = f"colleague-{uuid.uuid4().hex[:6]}@example.com"
    db.add(User(email=email, password_hash=hash_password("colleague-password-1")))
    await db.commit()
    csrf = await login(client)
    case_id = await make_case(client, csrf)

    r = await client.post(
        f"/cases/{case_id}/settings/share", data={"csrf_token": csrf, "email": "nobody@nowhere.example"}
    )
    assert r.headers["location"].endswith("error=no_user")
    r = await client.post(f"/cases/{case_id}/settings/share", data={"csrf_token": csrf, "email": email})
    assert r.headers["location"].endswith("saved=shared")

    await client.post("/logout", data={"csrf_token": csrf})
    csrf2 = await login(client, email, "colleague-password-1")
    assert (await client.get(f"/cases/{case_id}")).status_code == 200  # shared users can work the case
    r = await client.post(f"/cases/{case_id}/delete", data={"csrf_token": csrf2, "confirm_name": "x"})
    assert r.headers["location"].endswith("error=not_owner")
    r = await client.post(f"/cases/{case_id}/settings/share", data={"csrf_token": csrf2, "email": "admin@example.com"})
    assert r.headers["location"].endswith("error=not_owner")
    await client.post("/logout", data={"csrf_token": csrf2})

    csrf = await login(client)
    other = await db.scalar(select(User).where(User.email == email))
    await client.post(f"/cases/{case_id}/settings/unshare", data={"csrf_token": csrf, "user_id": str(other.id)})
    await client.post("/logout", data={"csrf_token": csrf})
    await login(client, email, "colleague-password-1")
    assert (await client.get(f"/cases/{case_id}")).status_code == 404


async def test_delete_requires_the_exact_name_and_keeps_the_audit_trail(client, db):
    csrf = await login(client)
    case_id = await make_case(client, csrf, name="Delete me please")
    r = await client.post(f"/cases/{case_id}/delete", data={"csrf_token": csrf, "confirm_name": "delete me"})
    assert r.headers["location"].endswith("error=confirm")
    assert await db.get(Investigation, case_id) is not None

    r = await client.post(f"/cases/{case_id}/delete", data={"csrf_token": csrf, "confirm_name": "Delete me please"})
    assert r.status_code == 303 and r.headers["location"] == "/"
    db.expire_all()
    assert await db.get(Investigation, case_id) is None
    actions = (
        (await db.execute(text("SELECT action FROM access_log WHERE detail->>'case_id' = :c"), {"c": str(case_id)}))
        .scalars()
        .all()
    )
    assert "delete_case" in actions and "create_case" in actions
    assert (await client.get(f"/cases/{case_id}")).status_code == 404
