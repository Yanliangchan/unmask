"""Legal and trust pages, security.txt, and per-user acceptance of the current Terms."""

import uuid

import pytest
from sqlalchemy import select

from app import legal
from app.config import get_settings
from app.models import AccessLog, User
from app.security import hash_password
from tests.conftest import csrf_from


@pytest.mark.parametrize(
    "path, phrase",
    [
        ("/terms", "Findings are probabilistic leads, not facts."),
        ("/terms", "Limitation of liability"),
        ("/terms", "defend, indemnify and hold harmless"),
        ("/acceptable-use", "stalk, harass, intimidate"),
        ("/trust", "Who is responsible for what"),
        ("/trust", "What leaves the platform"),
        ("/privacy", "If you are being researched"),
    ],
)
async def test_legal_pages_are_public_and_indexable(client, path, phrase):
    r = await client.get(path)
    assert r.status_code == 200 and phrase in r.text
    assert '<meta name="robots" content="index' in r.text
    assert 'href="/acceptable-use"' in r.text  # the page nav links every legal page


async def test_sitemap_robots_and_footer_list_the_legal_pages(client, monkeypatch):
    sitemap = (await client.get("/sitemap.xml")).text
    assert all(f"{p}</loc>" in sitemap for p in ("/trust", "/terms", "/acceptable-use", "/privacy"))
    monkeypatch.setattr(get_settings(), "allow_indexing", True)
    robots = (await client.get("/robots.txt")).text
    assert "Allow: /terms" in robots and "Disallow: /cases" in robots
    landing = (await client.get("/")).text
    assert 'href="/terms"' in landing and 'href="/trust"' in landing


async def test_operator_details_fill_the_pages_and_security_txt(client, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "security_contact", "")
    monkeypatch.setattr(s, "legal_contact", "")
    assert (await client.get("/.well-known/security.txt")).status_code == 404
    monkeypatch.setattr(s, "operator_name", "Example Intelligence Pte. Ltd.")
    monkeypatch.setattr(s, "legal_contact", "legal@example.com")
    monkeypatch.setattr(s, "security_contact", "security@example.com")
    monkeypatch.setattr(s, "governing_law", "England and Wales")
    terms = (await client.get("/terms")).text
    assert "Example Intelligence Pte. Ltd." in terms and "laws of England and Wales" in terms
    assert "mailto:legal@example.com" in terms
    txt = (await client.get("/.well-known/security.txt")).text
    assert "Contact: mailto:security@example.com" in txt and "/trust#disclosure" in txt and "Expires:" in txt


async def _new_user(client, db):
    email = f"legal-{uuid.uuid4().hex[:8]}@example.com"
    db.add(User(email=email, password_hash=hash_password("legal-password-1")))
    await db.commit()
    page = await client.get("/login")
    r = await client.post("/login", data={"email": email, "password": "legal-password-1",
                                          "csrf_token": csrf_from(page.text)})  # fmt: skip
    assert r.status_code == 303
    return email


async def test_new_users_must_accept_the_terms_before_anything_else(client, db):
    email = await _new_user(client, db)
    assert (await client.get("/")).headers["location"] == "/legal/accept"
    assert (await client.get("/cases/new")).headers["location"] == "/legal/accept?next=/cases/new"
    hx = await client.get("/cases/new", headers={"HX-Request": "true"})
    assert hx.headers["hx-redirect"].startswith("/legal/accept")
    assert (await client.get("/notifications/badge")).text == ""  # polled on every page: must not redirect
    assert (await client.get("/terms")).status_code == 200  # the terms themselves stay readable

    page = await client.get("/legal/accept?next=/cases/new")
    assert "Before you start" in page.text and legal.TERMS_VERSION in page.text
    csrf = csrf_from(page.text)
    refused = await client.post("/legal/accept", data={"csrf_token": csrf, "agree_terms": "on", "next": "/cases/new"})
    assert refused.status_code == 422 and "Tick both boxes" in refused.text

    ok = await client.post("/legal/accept", data={"csrf_token": csrf, "agree_terms": "on",
                                                  "agree_responsibility": "on", "next": "//evil.example"})  # fmt: skip
    assert ok.headers["location"] == "/"  # no open redirect
    user = await db.scalar(select(User).where(User.email == email))
    await db.refresh(user)
    assert user.terms_version == legal.TERMS_VERSION and user.terms_accepted_at is not None
    log = await db.scalar(select(AccessLog).where(AccessLog.user_id == user.id, AccessLog.action == "accept_terms"))
    assert log.detail["version"] == legal.TERMS_VERSION
    assert (await client.get("/cases/new")).status_code == 200


async def test_a_new_terms_version_asks_everyone_again(client, db, monkeypatch):
    await _new_user(client, db)
    page = await client.get("/legal/accept")
    await client.post("/legal/accept", data={"csrf_token": csrf_from(page.text), "agree_terms": "on",
                                             "agree_responsibility": "on"})  # fmt: skip
    assert (await client.get("/")).status_code == 200
    monkeypatch.setattr(legal, "TERMS_VERSION", "2099-01-01")
    assert (await client.get("/")).headers["location"] == "/legal/accept"
    assert "Our terms have changed" in (await client.get("/legal/accept")).text
