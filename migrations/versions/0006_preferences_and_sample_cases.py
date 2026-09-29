"""user preferences and Slack webhook, sample and templated cases

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-29 18:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0006'
down_revision: str | None = '0005'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('users', sa.Column('preferences', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False))
    op.add_column('users', sa.Column('slack_webhook', sa.Text(), nullable=True))
    op.add_column('investigations', sa.Column('is_sample', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    op.add_column('investigations', sa.Column('template', sa.String(length=40), nullable=True))
    op.create_index('ix_notifications_user_unread', 'notifications', ['user_id', 'read_at'])


def downgrade() -> None:
    op.drop_index('ix_notifications_user_unread', table_name='notifications')
    op.drop_column('investigations', 'template')
    op.drop_column('investigations', 'is_sample')
    op.drop_column('users', 'slack_webhook')
    op.drop_column('users', 'preferences')
