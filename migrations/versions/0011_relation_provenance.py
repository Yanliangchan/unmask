"""relation provenance: how each link was established, its direction, and when it was seen

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-21 15:00:00
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0011'
down_revision: str | None = '0010'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # observed: a tool reported it, or a fetched page shows it | rule: a deterministic string rule
    # similarity: a similarity score above a threshold | analyst: a person decided it
    op.add_column('relations', sa.Column('basis', sa.String(length=16), server_default=sa.text("'observed'"), nullable=False))
    op.add_column('relations', sa.Column('directed', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    op.add_column('relations', sa.Column('last_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False))
    op.add_column('relations', sa.Column('seen_count', sa.Integer(), server_default=sa.text('1'), nullable=False))
    op.add_column('relations', sa.Column('scan_run_id', sa.UUID(), nullable=True))
    op.add_column('relations', sa.Column('last_scan_run_id', sa.UUID(), nullable=True))
    op.create_foreign_key('fk_relations_scan_run', 'relations', 'scan_runs', ['scan_run_id'], ['id'], ondelete='SET NULL')
    op.create_foreign_key('fk_relations_last_scan_run', 'relations', 'scan_runs', ['last_scan_run_id'], ['id'], ondelete='SET NULL')
    op.create_check_constraint('ck_relations_basis', 'relations', "basis IN ('observed', 'rule', 'similarity', 'analyst')")
    # The "already linked?" lookup every scan makes for every finding.
    op.create_index('ix_relations_lookup', 'relations', ['entity_a_id', 'entity_b_id', 'relation_type', 'source_tool'])
    op.execute("UPDATE relations SET last_seen = created_at")
    op.execute("UPDATE relations SET basis = 'analyst' WHERE created_by LIKE 'analyst%'")
    op.execute(
        "UPDATE relations SET basis = 'similarity' WHERE created_by NOT LIKE 'analyst%' AND source_tool = 'correlation' "
        "AND relation_type IN ('possible_same', 'profile_name_match')"
    )
    op.execute(
        "UPDATE relations SET basis = 'rule' WHERE created_by NOT LIKE 'analyst%' AND source_tool = 'correlation' "
        "AND relation_type IN ('shares_handle', 'email_at_domain', 'same_as')"
    )
    # Tool-reported links run from what was searched to what was found; a profile links out.
    op.execute("UPDATE relations SET directed = true WHERE basis = 'observed'")


def downgrade() -> None:
    op.drop_index('ix_relations_lookup', table_name='relations')
    op.drop_constraint('ck_relations_basis', 'relations', type_='check')
    op.drop_constraint('fk_relations_last_scan_run', 'relations', type_='foreignkey')
    op.drop_constraint('fk_relations_scan_run', 'relations', type_='foreignkey')
    for col in ('last_scan_run_id', 'scan_run_id', 'seen_count', 'last_seen', 'directed', 'basis'):
        op.drop_column('relations', col)
