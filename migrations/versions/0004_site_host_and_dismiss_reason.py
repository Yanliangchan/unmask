"""per-site accuracy: account site host and the analyst's dismissal reason

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-29 12:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # site_host is filled in by the app (values are encrypted, so SQL can't derive it).
    op.add_column('entities', sa.Column('site_host', sa.String(length=255), nullable=True))
    op.add_column('entities', sa.Column('dismiss_reason', sa.String(length=32), nullable=True))
    op.create_index(op.f('ix_entities_site_host'), 'entities', ['site_host'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_entities_site_host'), table_name='entities')
    op.drop_column('entities', 'dismiss_reason')
    op.drop_column('entities', 'site_host')
