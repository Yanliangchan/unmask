"""observation provenance: what each sighting reported, from what, and where

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-21 18:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0012'
down_revision: str | None = '0011'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # What the tool reported this time (encrypted, like entity attributes), the page it came from,
    # the finding it was searched from, and the source grade at the time.
    op.add_column('entity_observations', sa.Column('reported', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('entity_observations', sa.Column('source_url', sa.Text(), nullable=True))
    op.add_column('entity_observations', sa.Column('parent_entity_id', sa.UUID(), nullable=True))
    op.add_column('entity_observations', sa.Column('reliability', sa.String(length=1), nullable=True))
    op.create_foreign_key('fk_observations_parent', 'entity_observations', 'entities', ['parent_entity_id'], ['id'], ondelete='SET NULL')
    # An analyst's own finding is an observation without a scan run.
    op.alter_column('entity_observations', 'scan_run_id', existing_type=sa.UUID(), nullable=True)


def downgrade() -> None:
    op.execute("DELETE FROM entity_observations WHERE scan_run_id IS NULL")
    op.alter_column('entity_observations', 'scan_run_id', existing_type=sa.UUID(), nullable=False)
    op.drop_constraint('fk_observations_parent', 'entity_observations', type_='foreignkey')
    for col in ('reliability', 'parent_entity_id', 'source_url', 'reported'):
        op.drop_column('entity_observations', col)
