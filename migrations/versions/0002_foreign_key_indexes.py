"""index foreign keys used by joins and cascades

Revision ID: 0002
Revises: 0001
Create Date: 2026-09-27 09:00:00
"""
from collections.abc import Sequence

from alembic import op

revision: str = '0002'
down_revision: str | None = '0001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# (table, column): the dashboard's "new since last review" count joins entities
# to scan_runs, and every SET NULL cascade on delete scans these columns.
INDEXES = [
    ('entities', 'scan_run_id'),
    ('entities', 'merged_into_id'),
    ('pivot_log', 'scan_run_id'),
    ('pivot_log', 'triggering_entity_id'),
    ('access_log', 'user_id'),
]


def upgrade() -> None:
    for table, column in INDEXES:
        op.create_index(op.f(f'ix_{table}_{column}'), table, [column], unique=False)


def downgrade() -> None:
    for table, column in reversed(INDEXES):
        op.drop_index(op.f(f'ix_{table}_{column}'), table_name=table)
