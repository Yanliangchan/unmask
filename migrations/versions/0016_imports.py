"""imported findings: an 'import' run type and an 'imported' link basis

Revision ID: 0016
Revises: 0015
Create Date: 2026-10-22 15:00:00
"""
from collections.abc import Sequence

from alembic import op

revision: str = '0016'
down_revision: str | None = '0015'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint('ck_relations_basis', 'relations', type_='check')
    op.create_check_constraint(
        'ck_relations_basis', 'relations', "basis IN ('observed', 'rule', 'similarity', 'analyst', 'imported')"
    )
    op.drop_constraint('ck_scan_runs_triggered_by', 'scan_runs', type_='check')
    op.create_check_constraint(
        'ck_scan_runs_triggered_by', 'scan_runs',
        "triggered_by IN ('manual', 'watch_mode', 'pivot_chain', 'health_check', 'import')",
    )


def downgrade() -> None:
    op.execute("DELETE FROM relations WHERE basis = 'imported'")
    op.execute("DELETE FROM scan_runs WHERE triggered_by = 'import'")
    op.drop_constraint('ck_scan_runs_triggered_by', 'scan_runs', type_='check')
    op.create_check_constraint(
        'ck_scan_runs_triggered_by', 'scan_runs',
        "triggered_by IN ('manual', 'watch_mode', 'pivot_chain', 'health_check')",
    )
    op.drop_constraint('ck_relations_basis', 'relations', type_='check')
    op.create_check_constraint(
        'ck_relations_basis', 'relations', "basis IN ('observed', 'rule', 'similarity', 'analyst')"
    )
