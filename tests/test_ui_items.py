"""Small workspace conveniences: score breakdown on hover, compact tables, citations, graph full screen."""

import html
import re
import uuid

from sqlalchemy import select

from app import jobs
from app.correlation.engine import correlate_and_commit
from app.models import Entity
from tests.conftest import case_form_data, login


async def _case(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"UI {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    await correlate_and_commit(db, case_id, semantic=False)
    return case_id, csrf


async def test_the_findings_table_explains_each_score_on_hover(client, db):
    case_id, _ = await _case(client, db)
    table = (await client.get(f"/cases/{case_id}/entities", params={"show": "all"})).text
    assert 'class="why-pop" role="tooltip"' in table and "how it was worked out" in table
    assert re.search(r'class="why-hover" tabindex="0" aria-describedby="why-[0-9a-f-]+"', table)
    page = (await client.get(f"/cases/{case_id}")).text
    assert "data-density" in page and ">Compact</button>" in page


async def test_a_finding_can_be_copied_as_a_citation(client, db):
    case_id, _ = await _case(client, db)
    e = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.type == "account").limit(1))
    drawer = (await client.get(f"/cases/{case_id}/entities/{e.id}/drawer")).text
    cite = html.unescape(re.search(r'data-copy="([^"]+)"', drawer).group(1))
    assert cite.startswith(f"{e.value} (account).") and "Reported by fake_ok" in cite
    assert f"({case_id}), retrieved" in cite and "source grade" in cite


async def test_the_graph_offers_full_screen_and_replay(client, db):
    case_id, _ = await _case(client, db)
    page = (await client.get(f"/cases/{case_id}/graph")).text
    assert 'data-gx="fullscreen"' in page and 'data-gx-f="asof"' in page and 'data-gx="play"' in page
