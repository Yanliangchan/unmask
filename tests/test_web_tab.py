"""The Web tab, findings added by hand, and single-tool scans."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import select

from app import crypto, jobs
from app.models import Entity, ScanRun
from tests.conftest import case_form_data, login


async def _case(client, csrf) -> uuid.UUID:
    r = await client.post("/cases", data=case_form_data(csrf, name=f"W {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    await jobs.wait_for_all()
    return uuid.UUID(r.headers["location"].rsplit("/", 1)[1])


async def _mention(db, case_id, url, *, found_by=("Exact match",), confirmed=False) -> Entity:
    now = datetime.now(UTC)
    e = Entity(
        case_id=case_id, type="web_mention", value=url, value_digest=crypto.digest("web_mention", url),
        attributes={"url": url, "host": "blog.example", "title": f"Title {url[-1]}", "snippet": "Jane Doe, Lisbon",
                    "found_by": list(found_by), "rank": 1},
        source_tool="websearch", confidence=0.3, source_reliability="D", confirmed_flag=confirmed,
        first_seen=now, last_verified=now,
    )  # fmt: skip
    db.add(e)
    await db.commit()
    return e


async def test_web_tab_explains_how_to_set_up_search_without_a_key(client, db):
    csrf = await login(client)
    case_id = await _case(client, csrf)
    page = await client.get(f"/cases/{case_id}/web")
    assert page.status_code == 200
    assert "Web search isn&#39;t set up" in page.text or "Web search isn't set up" in page.text
    assert "UNMASK_SERPER_KEY" in page.text and "Run web search" not in page.text


async def test_web_results_list_keep_and_set_aside(client, db):
    csrf = await login(client)
    case_id = await _case(client, csrf)
    a = await _mention(db, case_id, "https://blog.example/a", found_by=("Exact match", "With context: lisbon"))
    await _mention(db, case_id, "https://blog.example/b")
    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}

    results = (await client.get(f"/cases/{case_id}/web/results")).text
    assert results.index("Title a") < results.index("Title b")  # found by more searches ranks first
    assert "With context: lisbon" in results

    await client.post(f"/cases/{case_id}/entities/{a.id}/confirm", headers=headers)
    kept = (await client.get(f"/cases/{case_id}/web/results?show=kept")).text
    assert "Title a" in kept and "Title b" not in kept
    # A kept result joins the case's findings; the others stay out of the Entities view.
    table = (await client.get(f"/cases/{case_id}/entities")).text
    assert "blog.example/a" in table and "blog.example/b" not in table
    assert "1 web result in the" in table

    page = await client.get(f"/cases/{case_id}/web")
    assert 'Web<span class="count">2</span>' in page.text


async def test_analyst_can_add_a_finding_they_found_elsewhere(client, db):
    csrf = await login(client)
    case_id = await _case(client, csrf)
    r = await client.post(
        f"/cases/{case_id}/findings?from=web",
        data={"csrf_token": csrf, "type": "account", "value": "https://www.linkedin.com/in/janedoe", "note": "CV"},
    )
    assert r.status_code == 303 and r.headers["location"] == f"/cases/{case_id}/web?added=account"
    e = await db.scalar(
        select(Entity).where(Entity.case_id == case_id, Entity.source_tool == "analyst", Entity.is_seed.is_(False))
    )
    assert e.confirmed_flag and e.confidence == 1.0 and e.attributes["note"] == "CV"
    assert e.attributes["origin"] == "added by admin@example.com"
    assert "linkedin.com/in/janedoe" in (await client.get(f"/cases/{case_id}/entities")).text

    bad = await client.post(f"/cases/{case_id}/findings", data={"csrf_token": csrf, "type": "nonsense", "value": "x"})
    assert bad.status_code == 400


async def test_run_scan_can_be_limited_to_one_tool(client, db):
    csrf = await login(client)
    r = await client.post(
        "/cases", data=case_form_data(csrf, name=f"O {uuid.uuid4().hex[:6]}", tools=["fake_ok", "fake_fail"])
    )
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    await client.post(
        f"/cases/{case_id}/scans", data={"only": "fake_ok"}, headers={"HX-Request": "true", "X-CSRF-Token": csrf}
    )
    await jobs.wait_for_all()
    run = await db.scalar(select(ScanRun).where(ScanRun.case_id == case_id).order_by(ScanRun.run_number.desc()))
    assert run.run_number == 2 and run.tools_included == ["fake_ok"]
