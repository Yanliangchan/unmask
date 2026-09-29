"""saved entity views, notes on findings and notifications

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-29 15:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'saved_views',
        sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('params', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('case_id', 'user_id', 'name', name='uq_saved_views_name'),
    )
    op.create_index(op.f('ix_saved_views_case_id'), 'saved_views', ['case_id'], unique=False)
    op.create_index(op.f('ix_saved_views_user_id'), 'saved_views', ['user_id'], unique=False)
    op.create_table(
        'notes',
        sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=False),
        sa.Column('entity_id', sa.UUID(), nullable=True),
        sa.Column('author_id', sa.UUID(), nullable=True),
        sa.Column('body', sa.Text(), nullable=False),
        sa.Column('mentions', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['entity_id'], ['entities.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_notes_case_id'), 'notes', ['case_id'], unique=False)
    op.create_index(op.f('ix_notes_entity_id'), 'notes', ['entity_id'], unique=False)
    op.create_table(
        'notifications',
        sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
        sa.Column('user_id', sa.UUID(), nullable=False),
        sa.Column('case_id', sa.UUID(), nullable=True),
        sa.Column('kind', sa.String(length=32), nullable=False),
        sa.Column('text', sa.Text(), nullable=False),
        sa.Column('url', sa.Text(), nullable=True),
        sa.Column('read_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_notifications_user_id'), 'notifications', ['user_id'], unique=False)
    op.create_index(op.f('ix_notifications_case_id'), 'notifications', ['case_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_notifications_case_id'), table_name='notifications')
    op.drop_index(op.f('ix_notifications_user_id'), table_name='notifications')
    op.drop_table('notifications')
    op.drop_index(op.f('ix_notes_entity_id'), table_name='notes')
    op.drop_index(op.f('ix_notes_case_id'), table_name='notes')
    op.drop_table('notes')
    op.drop_index(op.f('ix_saved_views_user_id'), table_name='saved_views')
    op.drop_index(op.f('ix_saved_views_case_id'), table_name='saved_views')
    op.drop_table('saved_views')
