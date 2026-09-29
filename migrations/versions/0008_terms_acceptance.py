"""record which terms version each user accepted

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-29 22:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0008'
down_revision: str | None = '0007'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('users', sa.Column('terms_version', sa.String(length=20), nullable=True))
    op.add_column('users', sa.Column('terms_accepted_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'terms_accepted_at')
    op.drop_column('users', 'terms_version')
