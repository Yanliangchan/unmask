import uuid

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app import jobs
from app.models import AccessLog, Entity, Investigation, Relation, ScanRun, ToolConfig, User
from app.security import hash_password
from tests.conftest import case_form_data as case_form
from tests.conftest import csrf_from, login

# --- Public surface & SEO -------------------------------------------------------


async def test_landing_is_indexable_with_structured_data(client):
    r = await client.get("/")
    assert r.status_code == 200
    assert '<meta name="robots" content="index, follow' in r.text
    assert '<link rel="canonical" href="https://unmask.example/">' in r.text
    assert '"@type":"SoftwareApplication"' in r.text
    assert 'property="og:image"' in r.text
    assert "x-robots-tag" not in r.headers


async def test_private_pages_are_noindex(client):
    r = await client.get("/login")
    assert "noindex" in r.headers["x-robots-tag"]
    assert '<meta name="robots" content="noindex' in r.text


async def test_robots_and_sitemap(client):
    robots = (await client.get("/robots.txt")).text
    assert "Disallow: /cases" in robots
    assert "Sitemap: https://unmask.example/sitemap.xml" in robots
    sitemap = (await client.get("/sitemap.xml")).text
    assert "<loc>https://unmask.example/</loc>" in sitemap
    assert "/cases" not in sitemap


async def test_share_cards_and_icons(client):
    r = await client.get("/")
    for tag in (
        'property="og:image:width" content="1200"',
        'name="twitter:image"',
        'rel="apple-touch-icon"',
        "<title>unmask: self-hosted OSINT investigation platform</title>",
    ):
        assert tag in r.text
    manifest = (await client.get("/site.webmanifest")).json()
    assert {i["sizes"] for i in manifest["icons"]} >= {"192x192", "512x512"}
    assert "<lastmod>" in (await client.get("/sitemap.xml")).text


async def test_static_files_are_versioned_cached_and_compressed(client):
    import re

    page = (await client.get("/")).text
    css = re.search(r'href="(/static/css/app\.css\?v=[0-9a-f]{10})"', page).group(1)
    r = await client.get(css, headers={"accept-encoding": "gzip"})
    assert r.status_code == 200
    assert r.headers["cache-control"] == "public, max-age=31536000, immutable"
    assert r.headers["content-encoding"] == "gzip"
    # Unversioned URLs get a short cache; images are not re-compressed.
    png = await client.get("/static/img/og-image.png", headers={"accept-encoding": "gzip"})
    assert png.headers["cache-control"] == "public, max-age=3600"
    assert "content-encoding" not in png.headers
    # HTML carries CSRF tokens, so it is never compressed (BREACH).
    assert "content-encoding" not in (await client.get("/", headers={"accept-encoding": "gzip"})).headers


async def test_unknown_pages_get_the_styled_error_page(client):
    r = await client.get("/no-such-page", headers={"accept": "text/html"})
    assert r.status_code == 404
    assert "<h1>Not found</h1>" in r.text


async def test_security_headers(client):
    r = await client.get("/")
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


# --- Auth ---------------------------------------------------------------------


async def test_private_routes_require_login(client):
    r = await client.get("/cases/new")
    assert r.status_code == 303 and r.headers["location"].startswith("/login")


async def test_login_rejects_bad_password_then_rate_limits(app):
    import httpx

    transport = httpx.ASGITransport(app=app, client=("203.0.113.9", 4000))
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        token = csrf_from((await client.get("/login")).text)
        email = f"nobody-{uuid.uuid4().hex[:6]}@example.com"
        for _ in range(5):
            r = await client.post("/login", data={"email": email, "password": "nope", "csrf_token": token})
            assert r.status_code == 401
        r = await client.post("/login", data={"email": email, "password": "nope", "csrf_token": token})
        assert r.status_code == 429
        # The right password is refused too while the account is locked out.
        r = await client.post("/login", data={"email": email, "password": "correct-horse-battery", "csrf_token": token})
        assert r.status_code == 429


async def test_post_without_csrf_is_rejected(client):
    await login(client)
    r = await client.post("/cases", data=case_form(None))
    assert r.status_code == 403


async def test_login_does_not_open_redirect(client):
    page = await client.get("/login")
    r = await client.post(
        "/login",
        data={
            "email": "admin@example.com",
            "password": "correct-horse-battery",
            "next": "//evil.example",
            "csrf_token": csrf_from(page.text),
        },
    )
    assert r.headers["location"] == "/"


# --- Case creation gate ---------------------------------------------------------


@pytest.mark.parametrize(
    "override, message",
    [
        ({"lawful_basis_confirmed": None}, "lawful basis"),
        ({"authorization_note": "   "}, "authorization note"),
        ({"target_value": ""}, "at least one target"),
        ({"target_value": "not-an-email", "target_type": "email"}, "not a valid email"),
    ],
)
async def test_case_creation_is_blocked_without_requirements(client, db, override, message):
    csrf = await login(client)
    before = await db.scalar(select(Investigation.id).where(Investigation.name == "Blocked case"))
    r = await client.post("/cases", data=case_form(csrf, name="Blocked case", **override))
    assert r.status_code == 422
    assert message in r.text
    assert before is None
    assert await db.scalar(select(Investigation.id).where(Investigation.name == "Blocked case")) is None


async def test_database_rejects_case_without_lawful_basis(db):
    owner = await db.scalar(select(User.id))
    db.add(Investigation(name="x", authorization_note="note", lawful_basis_confirmed=False, owner_id=owner))
    with pytest.raises(IntegrityError):
        await db.commit()
    await db.rollback()


# --- Scanning -------------------------------------------------------------------


async def test_create_case_runs_scan_and_isolates_failures(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form(csrf, name="Scan case"))
    assert r.status_code == 303
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()

    run = await db.scalar(select(ScanRun).where(ScanRun.case_id == case_id))
    assert run.status == "partial"
    assert run.tools_completed == ["fake_ok"]
    assert run.tools_failed == ["fake_fail"]
    assert "HTTP 503" in run.failure_details["fake_fail"]
    assert run.jobs_done == run.jobs_total == 2

    entities = (await db.scalars(select(Entity).where(Entity.case_id == case_id))).all()
    by_type = {}
    for e in entities:
        by_type.setdefault(e.type, []).append(e)
    assert [e.value for e in by_type["username"]] == ["janedoe"]
    assert by_type["username"][0].is_seed
    assert sorted(e.value for e in by_type["account"]) == [
        "https://alpha.example/janedoe",
        "https://beta.example/janedoe",
    ]
    rels = (await db.scalars(select(Relation).where(Relation.case_id == case_id))).all()
    assert len(rels) == 2 and all(r.match_explanation for r in rels)

    # Sensitive values never hit the database in plaintext.
    raw = (
        await db.execute(text("SELECT value, attributes::text FROM entities WHERE case_id = :c"), {"c": case_id})
    ).all()
    assert all(v.startswith("enc:v1:") and "janedoe" not in v and "janedoe" not in a for v, a in raw)

    # Workspace and partials render the results.
    page = await client.get(f"/cases/{case_id}")
    assert page.status_code == 200 and "Scan case" in page.text
    assert "HTTP 503" in page.text
    table = await client.get(f"/cases/{case_id}/entities?min_confidence=0.3&tool=fake_ok")
    assert "https://alpha.example/janedoe" in table.text
    assert "janedoe</span>" not in table.text  # seed was filtered out by source


async def test_rescan_reuses_entities_and_records_observations(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form(csrf, name="Rescan case", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    r = await client.post(f"/cases/{case_id}/scans", data={"csrf_token": csrf})
    assert r.status_code == 303
    await jobs.wait_for_all()
    runs = (await db.scalars(select(ScanRun).where(ScanRun.case_id == case_id).order_by(ScanRun.run_number))).all()
    assert [r.run_number for r in runs] == [1, 2]
    assert all(r.status == "completed" for r in runs)
    count = await db.scalar(
        text("SELECT count(*) FROM entities WHERE case_id = :c AND type = 'account'"), {"c": case_id}
    )
    assert count == 2
    obs = await db.scalar(
        text("SELECT count(*) FROM entity_observations o JOIN entities e ON e.id = o.entity_id WHERE e.case_id = :c"),
        {"c": case_id},
    )
    assert obs == 4


async def test_signature_mismatch_is_a_failure_not_an_empty_result(client, db):
    csrf = await login(client)
    r = await client.post(
        "/cases", data=case_form(csrf, name="Blocked tool case", target_value="blocked", tools=["fake_ok"])
    )
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    run = await db.scalar(select(ScanRun).where(ScanRun.case_id == case_id))
    assert run.status == "failed"
    assert "bot-detection" in run.failure_details["fake_ok"]


async def test_circuit_breaker_disables_tool_after_three_failures(client, db):
    await db.execute(text("UPDATE tool_config SET enabled = true, consecutive_failures = 0, circuit_open = false"))
    await db.commit()
    csrf = await login(client)
    for i in range(3):
        await client.post("/cases", data=case_form(csrf, name=f"Breaker {i}", tools=["fake_fail"]))
        await jobs.wait_for_all()
    db.expire_all()
    cfg = await db.get(ToolConfig, "fake_fail")
    assert cfg.consecutive_failures == 3
    assert cfg.enabled is False and cfg.circuit_open is True
    home = await client.get("/")
    assert "the circuit breaker switched off" in home.text
    tools_page = await client.get("/tools")
    assert "auto-disabled by the circuit breaker" in tools_page.text

    # A disabled tool is no longer dispatched.
    r = await client.post("/cases", data=case_form(csrf, name="After breaker", tools=["fake_ok", "fake_fail"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    run = await db.scalar(select(ScanRun).where(ScanRun.case_id == case_id))
    assert run.tools_included == ["fake_ok"]

    # A passing health check closes the circuit.
    await db.execute(text("UPDATE tool_config SET enabled = false, circuit_open = true WHERE tool_name = 'fake_ok'"))
    await db.commit()
    r = await client.post("/tools/fake_ok/health-check", data={"csrf_token": csrf})
    assert r.status_code == 200
    db.expire_all()
    cfg = await db.get(ToolConfig, "fake_ok")
    assert cfg.enabled and not cfg.circuit_open and cfg.last_health_ok


async def test_cases_are_private_to_their_owner(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form(csrf, name="Private case", tools=["fake_ok"]))
    case_id = r.headers["location"].rsplit("/", 1)[1]
    await jobs.wait_for_all()

    db.add(User(email="other@example.com", password_hash=hash_password("other-password-123")))
    await db.commit()
    await client.post("/logout", data={"csrf_token": csrf})
    await login(client, "other@example.com", "other-password-123")
    assert (await client.get(f"/cases/{case_id}")).status_code == 404
    assert "Private case" not in (await client.get("/")).text


async def test_confirm_toggle_is_audited(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form(csrf, name="Confirm case", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    entity = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.type == "account"))
    r = await client.post(f"/cases/{case_id}/entities/{entity.id}/confirm", headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and "Confirmed" in r.text
    actions = (await db.scalars(select(AccessLog.action).where(AccessLog.case_id == case_id))).all()
    assert {"create_case", "run_scan", "confirm_entity"} <= set(actions)
