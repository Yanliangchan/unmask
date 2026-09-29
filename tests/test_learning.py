"""Learning from decisions: username commonness, per-site accuracy, reasons, the report and the eval harness."""

import json
import uuid

import httpx
import pytest
from sqlalchemy import select

from app import evaluation, jobs, verify
from app.adapters import registry
from app.adapters.base import EntityCandidate, RawResult, ToolAdapter
from app.adapters.sites import focused_sites
from app.correlation.commonness import username_rarity
from app.correlation.scoring import Evidence, score
from app.models import Entity
from app.services.accuracy import SiteStat, site_factor, site_host
from tests.conftest import case_form_data, login


def test_common_and_short_usernames_count_for_less():
    assert username_rarity("jo")[0] < username_rarity("john")[0] < username_rarity("janedoe")[0]
    assert username_rarity("mike92")[0] == 0.35
    assert username_rarity("jdoe_lisbon_1987")[0] == 1.0
    assert "common word or first name" in username_rarity("Admin")[1]


def test_site_factor_needs_a_few_decisions_then_moves_the_score():
    assert site_factor(SiteStat("x.com", confirmed=1, dismissed=1)) == (1.0, None)
    good, note = site_factor(SiteStat("github.com", confirmed=9, dismissed=1))
    bad, _ = site_factor(SiteStat("junk.example", confirmed=0, dismissed=8))
    assert good > 1.2 and bad < 0.8 and "confirmed 9 of 10" in note


def test_score_uses_rarity_and_site_record_and_keeps_the_model_score_when_confirmed():
    base = Evidence(prior=0.4, reliability="C", sources=1, verification="verified")
    plain = score(base).overall
    common = score(Evidence(**{**base.__dict__, "rarity": 0.25, "rarity_note": "common"})).overall
    trusted = score(Evidence(**{**base.__dict__, "site_factor": 1.3, "site_note": "good record"})).overall
    assert common < plain < trusted
    confirmed = score(Evidence(**{**base.__dict__, "confirmed": True}))
    assert confirmed.overall == 1.0 and confirmed.components["evidence.model_score"] == plain


def test_focused_site_lists_are_the_default(monkeypatch):
    from app.config import get_settings

    sherlock = focused_sites("sherlock")
    assert "GitHub" in sherlock and 100 < len(sherlock) < 140
    monkeypatch.setattr(get_settings(), "username_sites", "all")
    assert focused_sites("maigret") is None


def test_site_host():
    assert site_host("https://www.GitHub.com/janedoe") == "github.com"
    assert site_host("https://m.facebook.com/x") == "facebook.com"


async def test_not_them_reasons_feed_the_accuracy_report(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"A {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    accounts = {
        e.attributes["site"]: e
        for e in (await db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "account"))).all()
    }
    headers = {"HX-Request": "true", "X-CSRF-Token": csrf}
    await client.post(f"/cases/{case_id}/entities/{accounts['alpha'].id}/confirm", headers=headers)
    await client.post(
        f"/cases/{case_id}/entities/{accounts['beta'].id}/dismiss", data={"reason": "not_a_profile"}, headers=headers
    )
    await db.refresh(accounts["beta"])
    assert accounts["beta"].dismiss_reason == "not_a_profile"
    assert accounts["beta"].site_host == "beta.example"

    page = (await client.get("/tools")).text
    assert "How accurate are the results?" in page
    assert "beta.example" in page and "Not a real profile" in page
    await client.post(f"/cases/{case_id}/entities/{accounts['beta'].id}/restore", headers=headers)
    await db.refresh(accounts["beta"])
    assert accounts["beta"].dismiss_reason is None


# --- Evaluation harness ------------------------------------------------------------------------


class FakeEvalAdapter(ToolAdapter):
    name = "fake_eval"
    label = "Fake Eval"
    input_types = ["username"]
    verify_accounts = True

    async def run(self, target_value, context_tags):
        return [RawResult(self.name, target_value, None)]

    def parse(self, raw):
        return [
            EntityCandidate(type="account", value=url, attributes={"url": url, "username": raw.target_value})
            for url in (
                f"https://real.example/{raw.target_value}",
                f"https://gone.example/{raw.target_value}",
                f"https://other.example/{raw.target_value}",
            )
        ]


def _pages(request):
    if request.url.host in ("real.example", "other.example"):
        return httpx.Response(200, html=f"<title>{request.url.path.strip('/')} profile</title>")
    return httpx.Response(404)


@pytest.fixture
def eval_env(monkeypatch):
    monkeypatch.setattr(verify, "transport", httpx.MockTransport(_pages))
    registry.register(FakeEvalAdapter())
    yield
    registry.unregister("fake_eval")


def test_eval_file_must_record_authorization(tmp_path):
    f = tmp_path / "e.json"
    f.write_text(json.dumps({"identities": [{"username": "x", "expected": ["https://a.example/x"]}]}))
    with pytest.raises(evaluation.EvalFileError, match="authorization"):
        evaluation.load(f)


async def test_eval_reports_precision_and_recall_before_and_after_the_page_check(eval_env):
    data = {
        "authorization": "own accounts",
        "identities": [
            {"label": "me", "username": "janedoe",
             "expected": ["https://real.example/janedoe", "https://missing.example/janedoe"]},
        ],
    }  # fmt: skip
    [r] = await evaluation.run_eval(data, ["fake_eval"])
    assert (r.reported, r.reported_correct, r.shown, r.shown_correct) == (3, 1, 2, 1)
    assert r.precision_reported == 0.333 and r.precision_shown == 0.5 and r.recall_shown == 0.5
    assert r.missed == ["missing.example/janedoe"] and r.false_positives == ["other.example/janedoe"]
    text = evaluation.summarize([r])
    assert "fake_eval" in text and "shown precision   50%" in text
    [unconfigured] = await evaluation.run_eval(data, ["no_such_tool"])
    assert unconfigured.error == "unknown tool"
