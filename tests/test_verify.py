"""Profile-page verification of account hits."""

import uuid

import httpx
import pytest
from sqlalchemy import select

from app import jobs, verify
from app.adapters import registry
from app.adapters.base import EntityCandidate, RawResult, ToolAdapter
from app.models import Entity, ScanRun
from app.services.tools import sync_tool_config
from app.verify import REJECTED, UNVERIFIED, VERIFIED, classify
from tests.conftest import case_form_data, login

PROFILE = """<html><head><title>janedoe (Jane Doe) · Example</title>
<meta property="og:title" content="Jane Doe (janedoe)">
<meta property="og:description" content="Logistics lead in Lisbon">
<meta property="og:image" content="https://cdn.example/a.png"></head><body>hi</body></html>"""


# --- classify ------------------------------------------------------------------------


def test_profile_that_names_the_username_is_verified_with_a_preview():
    v = classify("https://x.example/janedoe", "janedoe", 200, "https://x.example/janedoe", PROFILE)
    assert v.status == VERIFIED
    assert v.preview["title"] == "Jane Doe (janedoe)"
    assert v.preview["description"] == "Logistics lead in Lisbon"


def test_username_match_ignores_separators_and_case():
    page = "<title>Jane_Doe on Example</title>"
    assert (
        classify("https://x.example/jane.doe", "jane.doe", 200, "https://x.example/jane.doe", page).status == VERIFIED
    )


@pytest.mark.parametrize(
    ("status", "final", "page", "expected", "reason"),
    [
        (404, None, "<title>Oops</title>", REJECTED, "page not found"),
        (200, None, "<title>Page not found · Example</title>", REJECTED, "does not exist"),
        (
            200,
            None,
            "<title>Example</title><body><h1>Sorry, this user doesn't exist</h1></body>",
            REJECTED,
            "does not exist",
        ),
        (200, "https://x.example/login?next=/janedoe", "<title>Log in</title>", REJECTED, "login page"),
        (200, "https://x.example/", "<title>Example home</title>", REJECTED, "redirects away"),
        (403, None, "<title>Forbidden</title>", UNVERIFIED, "bot protection"),
        (200, None, "<title>Just a moment...</title>", UNVERIFIED, "bot protection"),
        (200, None, "<title>Log in to Example</title>", UNVERIFIED, "login wall"),
        (200, None, "<title>Example</title><body>links: /janedoe</body>", UNVERIFIED, "not as its subject"),
        (200, None, "<title>Example</title><body>welcome</body>", UNVERIFIED, "does not mention"),
    ],
)
def test_classify_rejects_or_doubts_pages_that_do_not_prove_an_account(status, final, page, expected, reason):
    url = "https://x.example/janedoe"
    v = classify(url, "janedoe", status, final or url, page)
    assert v.status == expected
    assert reason in v.reason


# --- verify_candidates -----------------------------------------------------------------


def _account(site: str, username: str = "janedoe") -> EntityCandidate:
    url = f"https://{site}.example/{username}"
    return EntityCandidate(type="account", value=url, attributes={"site": site, "url": url, "username": username})


def _pages(request: httpx.Request) -> httpx.Response:
    host = request.url.host
    if host == "real.example":
        return httpx.Response(200, html=PROFILE)
    if host == "gone.example":
        return httpx.Response(404, html="<title>Not here</title>")
    if host == "wall.example":
        return httpx.Response(403, html="<title>Attention Required! | Cloudflare</title>")
    raise httpx.ConnectTimeout("timed out", request=request)


@pytest.fixture
def mock_pages(monkeypatch):
    monkeypatch.setattr(verify, "transport", httpx.MockTransport(_pages))


async def test_verify_candidates_drops_rejected_and_annotates_the_rest(mock_pages):
    email = EntityCandidate(type="email", value="a@b.example")
    cands = [_account("real"), _account("gone"), _account("wall"), _account("slow"), email]
    kept, stats = await verify.verify_candidates(cands)
    by_site = {c.attributes.get("site"): c for c in kept}
    assert set(by_site) == {"real", "wall", "slow", None}
    assert by_site["real"].attributes["verification"] == VERIFIED
    assert by_site["real"].attributes["preview"]["description"] == "Logistics lead in Lisbon"
    assert by_site["wall"].attributes["verification"] == UNVERIFIED
    assert "ConnectTimeout" in by_site["slow"].attributes["verification_reason"]
    assert stats.counts == {VERIFIED: 1, REJECTED: 1, UNVERIFIED: 2}


async def test_verification_can_be_switched_off(mock_pages, monkeypatch):
    from app.config import get_settings

    monkeypatch.setattr(get_settings(), "verify_accounts", False)
    kept, stats = await verify.verify_candidates([_account("gone")])
    assert len(kept) == 1 and not stats.counts


# --- end to end ------------------------------------------------------------------------------


class FakeCheckedAdapter(ToolAdapter):
    """A username tool whose hits go through page verification."""

    name = "fake_checked"
    label = "Fake Checked"
    input_types = ["username"]
    verify_accounts = True

    async def run(self, target_value, context_tags):
        return [RawResult(self.name, target_value, None)]

    def parse(self, raw):
        return [_account(site, raw.target_value) for site in ("real", "gone", "wall")]


@pytest.fixture
async def checked_env(db, mock_pages):
    registry.register(FakeCheckedAdapter())
    await sync_tool_config(db)
    yield
    registry.unregister("fake_checked")


async def test_scan_keeps_verified_hits_ranks_them_above_unverified_and_counts_rejections(client, db, checked_env):
    csrf = await login(client)
    r = await client.post(
        "/cases",
        data=case_form_data(csrf, name=f"V {uuid.uuid4().hex[:6]}", target_value="janedoe", tools=["fake_checked"]),
    )
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    accounts = {
        e.attributes["site"]: e
        for e in (await db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.type == "account"))).all()
    }
    assert set(accounts) == {"real", "wall"}  # the 404 page never became a finding
    assert accounts["real"].verification == VERIFIED
    assert accounts["wall"].verification == UNVERIFIED
    assert accounts["real"].confidence > 0.5 > accounts["wall"].confidence
    run = await db.scalar(select(ScanRun).where(ScanRun.case_id == case_id))
    counts = run.failure_details["_verification"]["fake_checked"]["counts"]
    assert counts == {VERIFIED: 1, UNVERIFIED: 1, REJECTED: 1}
