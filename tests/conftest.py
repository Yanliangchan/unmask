"""Test fixtures.

Integration tests need a disposable Postgres database, given as
TEST_DATABASE_URL. The schema is rebuilt from the Alembic migrations, so the
migrations themselves are exercised on every run.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parent.parent

TEST_DB = os.environ.get("TEST_DATABASE_URL")
os.environ["DATABASE_URL"] = TEST_DB or "postgresql://invalid/invalid"
os.environ["UNMASK_DATA_KEYS"] = Fernet.generate_key().decode()
os.environ["UNMASK_INDEX_KEY"] = "test-index-key"
os.environ["UNMASK_ADMIN_EMAIL"] = "admin@example.com"
os.environ["UNMASK_ADMIN_PASSWORD"] = "correct-horse-battery"
# Unreachable on purpose: the login limiter falls back to memory.
os.environ["REDIS_URL"] = "redis://127.0.0.1:1/0"
# Optional real Redis for the RQ integration tests.
TEST_REDIS = os.environ.get("TEST_REDIS_URL")
os.environ["PUBLIC_BASE_URL"] = "https://unmask.example"
# Tests drive the scheduler explicitly.
os.environ["UNMASK_SCHEDULER"] = "false"

# Freeze settings now, so tests that patch os.environ can't leak into them.
from app.config import get_settings  # noqa: E402

get_settings()

requires_db = pytest.mark.skipif(not TEST_DB, reason="TEST_DATABASE_URL not set")


@pytest.fixture(scope="session")
def migrated_db():
    if not TEST_DB:
        pytest.skip("TEST_DATABASE_URL not set")
    alembic = [sys.executable, "-m", "alembic"]
    subprocess.run([*alembic, "downgrade", "base"], cwd=ROOT, check=True, env=os.environ)
    subprocess.run([*alembic, "upgrade", "head"], cwd=ROOT, check=True, env=os.environ)
    yield


@pytest.fixture(scope="session")
async def app(migrated_db):
    from app.adapters import registry
    from app.main import app as fastapi_app
    from tests.fakes import FakeFailingAdapter, FakeUsernameAdapter

    for adapter in registry.all_adapters():
        registry.unregister(adapter.name)
    registry.register(FakeUsernameAdapter())
    registry.register(FakeFailingAdapter())
    async with fastapi_app.router.lifespan_context(fastapi_app):
        yield fastapi_app


@pytest.fixture
async def client(app):
    import httpx

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


@pytest.fixture
async def db(app):
    from app.db import sessionmaker

    async with sessionmaker()() as session:
        yield session


def csrf_from(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "no csrf token in page"
    return m.group(1)


async def login(client, email="admin@example.com", password="correct-horse-battery"):  # noqa: S107
    page = await client.get("/login")
    token = csrf_from(page.text)
    resp = await client.post("/login", data={"email": email, "password": password, "csrf_token": token})
    assert resp.status_code == 303, resp.text
    home = await client.get("/")
    if home.status_code == 303 and home.headers["location"].startswith("/legal/accept"):
        page = await client.get("/legal/accept")
        await client.post("/legal/accept", data={"csrf_token": csrf_from(page.text), "agree_terms": "on",
                                                 "agree_responsibility": "on"})  # fmt: skip
        home = await client.get("/")
    return csrf_from(home.text)


def case_form_data(csrf, **overrides):
    data = {
        "csrf_token": csrf,
        "name": "Test case",
        "authorization_note": "Written consent from subject, ref T-1",
        "lawful_basis_confirmed": "on",
        "target_value": "janedoe",
        "target_type": "username",
        "target_tags": "london, fintech",
        "tools": ["fake_ok", "fake_fail"],
    }
    data.update(overrides)
    return {k: v for k, v in data.items() if v is not None}
