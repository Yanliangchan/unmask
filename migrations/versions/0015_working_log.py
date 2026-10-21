"""case working log: case-level notes and pinned findings and links

Revision ID: 0015
Revises: 0014
Create Date: 2026-10-22 12:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0015'
down_revision: str | None = '0014'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # note: on a finding (entity_id set); log: a case-level entry; pin: a finding or link kept on the log.
    op.add_column('notes', sa.Column('kind', sa.String(length=8), server_default=sa.text("'note'"), nullable=False))
    op.add_column('notes', sa.Column('relation_id', sa.UUID(), nullable=True))
    op.create_foreign_key('fk_notes_relation', 'notes', 'relations', ['relation_id'], ['id'], ondelete='CASCADE')
    op.create_index('ix_notes_relation_id', 'notes', ['relation_id'])
    op.create_check_constraint('ck_notes_kind', 'notes', "kind IN ('note', 'log', 'pin')")
    op.create_check_constraint(
        'ck_notes_pin_target', 'notes',
        "kind <> 'pin' OR (entity_id IS NOT NULL) <> (relation_id IS NOT NULL)",
    )


def downgrade() -> None:
    op.drop_constraint('ck_notes_pin_target', 'notes', type_='check')
    op.drop_constraint('ck_notes_kind', 'notes', type_='check')
    op.drop_index('ix_notes_relation_id', table_name='notes')
    op.drop_constraint('fk_notes_relation', 'notes', type_='foreignkey')
    op.drop_column('notes', 'relation_id')
    op.drop_column('notes', 'kind')
