"""The analyst assessment is case content: encrypted at rest, and migration 0017 encrypts old rows."""

import asyncio
import os
import subprocess
import sys
import uuid
from pathlib import Path

from sqlalchemy import text

from app import jobs
from app.models import Investigation
from tests.conftest import case_form_data, login

ROOT = Path(__file__).resolve().parent.parent
SECRET = "The handle janedoe on alpha is the subject; beta is a namesake in Leeds."


async def _alembic(*args: str) -> None:
    await asyncio.to_thread(
        subprocess.run, [sys.executable, "-m", "alembic", *args], cwd=ROOT, check=True, env=os.environ
    )


async def _raw(db, case_id):
    return (
        await db.execute(text("SELECT analyst_assessment FROM investigations WHERE id = :id"), {"id": case_id})
    ).scalar()


async def test_assessment_is_stored_encrypted_and_reads_back(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"Enc {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    await client.post(f"/cases/{case_id}/settings/assessment", data={"csrf_token": csrf, "analyst_assessment": SECRET})

    stored = await _raw(db, case_id)
    assert stored.startswith("enc:v1:") and "janedoe" not in stored and "Leeds" not in stored
    db.expire_all()
    assert (await db.get(Investigation, case_id)).analyst_assessment == SECRET
    # Everything that shows it still shows the words, not the ciphertext.
    assert "Leeds" in (await client.get(f"/cases/{case_id}/deliver")).text
    assert "Leeds" in (await client.get(f"/cases/{case_id}/report")).text


async def test_migration_encrypts_existing_plain_text_and_is_safe_to_rerun(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"Old {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    # A row written before 0017: plain text in the column.
    await db.execute(
        text("UPDATE investigations SET analyst_assessment = :v WHERE id = :id"), {"v": SECRET, "id": case_id}
    )
    await db.commit()

    await _alembic("downgrade", "0016")
    assert await _raw(db, case_id) == SECRET  # downgrade leaves plain text alone (and decrypts the rest)
    await _alembic("upgrade", "head")
    once = await _raw(db, case_id)
    assert once.startswith("enc:v1:") and "janedoe" not in once
    await _alembic("downgrade", "0016")
    assert await _raw(db, case_id) == SECRET
    await _alembic("upgrade", "head")
    db.expire_all()
    assert (await db.get(Investigation, case_id)).analyst_assessment == SECRET
