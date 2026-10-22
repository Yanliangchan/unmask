"""Case navigation, the Report tab's hand-off, reasons in words, and the review entry point."""

import html
import re
import uuid

from sqlalchemy import select

from app import jobs
from app.correlation.engine import correlate_and_commit
from app.models import AccessLog, ShareLink
from app.services.signals import Evidence, Signal
from tests.conftest import case_form_data, login


async def _case(client, db, assess=True):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"UX {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    await correlate_and_commit(db, case_id, semantic=False)
    if assess:
        written = {"csrf_token": csrf, "analyst_assessment": "The handle janedoe on alpha is the subject."}
        await client.post(f"/cases/{case_id}/settings/assessment", data=written)
    return case_id, csrf


async def test_four_sections_with_their_pages_and_settings_apart(client, db):
    case_id, _ = await _case(client, db, assess=False)
    page = (await client.get(f"/cases/{case_id}/pivots")).text
    nav = page[
        page.index('aria-label="Case sections"') : page.index("</nav>", page.index('aria-label="Case sections"'))
    ]
    assert [m for m in re.findall(r">(Findings|Graph|Log|Report)<?", nav)] == ["Findings", "Graph", "Log", "Report"]
    assert 'class="tab-gear"' in nav
    # The Log section shows its own pages, with the current one marked.
    assert re.search(r'href="/cases/[^"]+/pivots" aria-current="page">Follow-ups', page)
    assert "Working log" in page and "Activity" in page
    for path in ("", "/web", "/graph", "/timeline", "/log", "/pivots", "/activity", "/deliver", "/settings"):
        assert (await client.get(f"/cases/{case_id}{path}")).status_code == 200, path


async def test_the_report_tab_prepares_a_hand_off_in_one_step(client, db):
    case_id, csrf = await _case(client, db)
    tab = (await client.get(f"/cases/{case_id}/deliver")).text
    assert "Send the report" in tab and "Prepare to send" in tab and "Download the report" in tab
    r = await client.post(f"/cases/{case_id}/handoff",
                          data={"csrf_token": csrf, "recipient": "Priya", "detail": "brief", "days": "7"})  # fmt: skip
    assert r.status_code == 200 and "Ready to send to Priya" in r.text
    assert f"/cases/{case_id}/download?f=pdf&amp;detail=brief" in r.text
    message = html.unescape(re.search(r'data-copy="([^"]+)" data-copied="Message copied."', r.text).group(1))
    url = re.search(r"(http://testserver/s/\S+)", message).group(1)
    assert message.startswith("Hi Priya,") and "TLP:AMBER" in message and "admin@example.com" in message
    assert (await client.get(url.replace("http://testserver", ""))).status_code == 200  # the link works
    link = await db.scalar(select(ShareLink).where(ShareLink.case_id == case_id))
    assert link.label == "Priya"
    assert await db.scalar(select(AccessLog).where(AccessLog.case_id == case_id, AccessLog.action == "handoff"))


async def test_the_hand_off_needs_the_assessment(client, db):
    case_id, csrf = await _case(client, db, assess=False)
    tab = (await client.get(f"/cases/{case_id}/deliver")).text
    assert "Prepare to send" not in tab and "Write your assessment below first" in tab
    r = await client.post(f"/cases/{case_id}/handoff", data={"csrf_token": csrf})
    assert r.status_code == 303 and r.headers["location"].endswith("/deliver?error=assessment")


def test_a_reason_names_the_strongest_case_for_and_the_main_one_against():
    ev = Evidence(for_=[Signal("Found by 2 tools"), Signal("Corroborated"), Signal("Corroborated")])
    assert ev.reason == "Corroborated · Found by 2 tools"  # strongest first, and each kind once
    ev.against.append(Signal("Common username: a match means little"))
    assert ev.reason == "Corroborated, but common username: a match means little"
    assert Evidence(notes=[Signal("Profile page not checked")]).reason == "Profile page not checked"
    assert Evidence().reason == "No evidence either way"


async def test_findings_rows_carry_reasons_and_a_way_into_review(client, db):
    case_id, _ = await _case(client, db, assess=False)
    table = (await client.get(f"/cases/{case_id}/entities", params={"show": "all"})).text
    assert 'class="row-reason' in table
    page = (await client.get(f"/cases/{case_id}")).text
    assert re.search(r'href="/cases/[^"]+/review" data-review-link>Review \d+ undecided', page)
    card = (await client.get(f"/cases/{case_id}/review/next")).text
    assert "<progress" in card and 'class="review-reason' in card
