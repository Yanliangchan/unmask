"""page snapshots and expiring share links

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-29 20:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0007'
down_revision: str | None = '0006'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'snapshots',
        sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('entity_id', sa.UUID(), nullable=True),
        sa.Column('url', sa.Text(), nullable=False),
        sa.Column('final_url', sa.Text(), nullable=False),
        sa.Column('status_code', sa.Integer(), nullable=False),
        sa.Column('content_type', sa.String(length=200), server_default=sa.text("''"), nullable=False),
        sa.Column('sha256', sa.String(length=64), nullable=False),
        sa.Column('size', sa.Integer(), nullable=False),
        sa.Column('truncated', sa.Boolean(), server_default=sa.text('false'), nullable=False),
        sa.Column('title', sa.Text(), nullable=True),
        sa.Column('body_b64', sa.Text(), nullable=False),
        sa.Column('captured_by', sa.UUID(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['entity_id'], ['entities.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['captured_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_snapshots_case_id'), 'snapshots', ['case_id'])
    op.create_index(op.f('ix_snapshots_entity_id'), 'snapshots', ['entity_id'])
    op.create_table(
        'share_links',
        sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('label', sa.String(length=120), nullable=True),
        sa.Column('created_by', sa.UUID(), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('views', sa.Integer(), server_default=sa.text('0'), nullable=False),
        sa.Column('last_viewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )
    op.create_index(op.f('ix_share_links_case_id'), 'share_links', ['case_id'])


def downgrade() -> None:
    op.drop_index(op.f('ix_share_links_case_id'), table_name='share_links')
    op.drop_table('share_links')
    op.drop_index(op.f('ix_snapshots_entity_id'), table_name='snapshots')
    op.drop_index(op.f('ix_snapshots_case_id'), table_name='snapshots')
    op.drop_table('snapshots')
