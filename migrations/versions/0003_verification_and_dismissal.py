"""account verification status and analyst dismissal

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-29 10:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('entities', sa.Column('dismissed_flag', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    op.add_column('entities', sa.Column('verification', sa.String(length=12), nullable=True))


def downgrade() -> None:
    op.drop_column('entities', 'verification')
    op.drop_column('entities', 'dismissed_flag')
