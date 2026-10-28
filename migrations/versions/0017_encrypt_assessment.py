"""encrypt the analyst assessment at rest, like the rest of the case's content

Revision ID: 0017
Revises: 0016
Create Date: 2026-10-28 09:00:00

Needs UNMASK_DATA_KEYS (and UNMASK_INDEX_KEY) set, as the app does. Rows that are already
encrypted are left alone, so running it twice is harmless.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0017"
down_revision: str | None = "0016"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PREFIX = "enc:v1:"


def _rows(conn):
    return conn.execute(
        sa.text("SELECT id, analyst_assessment FROM investigations WHERE analyst_assessment IS NOT NULL")
    ).all()


def upgrade() -> None:
    from app import crypto

    conn = op.get_bind()
    for case_id, text in _rows(conn):
        if not text.startswith(PREFIX):
            conn.execute(
                sa.text("UPDATE investigations SET analyst_assessment = :v WHERE id = :id"),
                {"v": crypto.encrypt(text), "id": case_id},
            )


def downgrade() -> None:
    from cryptography.fernet import InvalidToken

    from app import crypto

    conn = op.get_bind()
    unreadable = 0
    for case_id, text in _rows(conn):
        if not text.startswith(PREFIX):
            continue
        try:
            plain = crypto.decrypt(text)
        except InvalidToken:
            # Encrypted under a key this deployment no longer has: leave it, never corrupt it.
            unreadable += 1
            continue
        conn.execute(sa.text("UPDATE investigations SET analyst_assessment = :v WHERE id = :id"),
                     {"v": plain, "id": case_id})
    if unreadable:
        print(f"0017 downgrade: {unreadable} assessment(s) couldn't be decrypted with the current keys; left as is")
