"""Creating a case: pasted identifiers, shared context and the Quick / Deep choice."""

import uuid

import pytest
from sqlalchemy import select

from app import jobs
from app.adapters import registry
from app.adapters.base import RawResult, ToolAdapter
from app.identifiers import guess_type, split_identifiers
from app.models import Investigation, ScanRun, Target
from app.services.tools import sync_tool_config
from tests.conftest import case_form_data, login


def test_identifier_detection():
    assert [guess_type(v) for v in ("jane@acme.example", "8.8.8.8", "+351 912 345 678", "acme.example",
                                    "https://www.acme.example/about", "Jane Doe", "janedoe")] == [
        "email", "ip", "phone", "domain", "domain", "name", "username"]  # fmt: skip
    assert split_identifiers("janedoe\nJane Doe, janedoe; https://acme.example/x\n\n") == [
        ("janedoe", "username"), ("Jane Doe", "name"), ("acme.example", "domain")]  # fmt: skip


class FakeSlowTool(ToolAdapter):
    name = "fake_deep"
    label = "Fake Deep"
    input_types = ["username"]
    speed = "slow"

    async def run(self, target_value, context_tags):
        return [RawResult(self.name, target_value, None)]

    def parse(self, raw):
        return []


@pytest.fixture
async def slow_tool(db):
    registry.register(FakeSlowTool())
    await sync_tool_config(db)
    yield
    registry.unregister("fake_deep")


async def _create(client, csrf, **fields):
    data = case_form_data(csrf, name=f"N {uuid.uuid4().hex[:6]}", **fields)
    r = await client.post("/cases", data=data)
    assert r.status_code == 303, r.text
    await jobs.wait_for_all()
    return uuid.UUID(r.headers["location"].rsplit("/", 1)[1])


async def test_pasted_identifiers_and_shared_context_become_targets(client, db):
    csrf = await login(client)
    case_id = await _create(
        client,
        csrf,
        target_value="",
        target_tags="",
        paste="janedoe\njane@acme.example\nJane Doe",
        context="lisbon, acme",
    )
    targets = (await db.scalars(select(Target).where(Target.case_id == case_id))).all()
    assert sorted((t.type, t.value) for t in targets) == [
        ("email", "jane@acme.example"), ("name", "Jane Doe"), ("username", "janedoe")]  # fmt: skip
    assert all(t.context_tags == ["lisbon", "acme"] for t in targets)


async def test_quick_leaves_out_slow_tools_and_deep_keeps_them(client, db, slow_tool):
    csrf = await login(client)
    quick = await _create(client, csrf, tools=["fake_ok", "fake_deep"], depth="quick")
    deep = await _create(client, csrf, tools=["fake_ok", "fake_deep"], depth="deep")
    runs = {
        r.case_id: r.tools_included
        for r in (await db.scalars(select(ScanRun).where(ScanRun.case_id.in_([quick, deep])))).all()
    }
    assert runs[quick] == ["fake_ok"] and runs[deep] == ["fake_deep", "fake_ok"]
    case = await db.get(Investigation, quick)
    assert "fake_deep" in case.disabled_tools


async def test_new_case_form_offers_paste_context_and_depth(client, slow_tool):
    await login(client)
    page = (await client.get("/cases/new")).text
    assert 'name="paste"' in page and 'name="context"' in page
    assert 'value="quick" data-depth checked' in page and "Adds Fake Deep" in page
    # Quick is the default, so slow tools start unticked.
    assert 'value="fake_deep" data-speed="slow"\n' in page or 'value="fake_deep" data-speed="slow"' in page
    fake_deep_line = next(line for line in page.splitlines() if 'value="fake_deep"' in line)
    next_line = page.splitlines()[page.splitlines().index(fake_deep_line) + 1]
    assert "checked" not in next_line
