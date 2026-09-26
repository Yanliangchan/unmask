"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-09-26 08:18:32.044035
"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = '0001'
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table('tool_config',
    sa.Column('tool_name', sa.Text(), nullable=False),
    sa.Column('enabled', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('max_concurrent', sa.Integer(), server_default=sa.text('3'), nullable=False),
    sa.Column('delay_between_requests_ms', sa.Integer(), server_default=sa.text('500'), nullable=False),
    sa.Column('consecutive_failures', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('circuit_open', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('last_success_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_failure_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_failure_reason', sa.Text(), nullable=True),
    sa.Column('last_health_check_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_health_ok', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('tool_name')
    )
    op.create_table('users',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('email', sa.String(length=320), nullable=False),
    sa.Column('display_name', sa.String(length=200), nullable=True),
    sa.Column('password_hash', sa.Text(), nullable=False),
    sa.Column('is_admin', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('is_active', sa.Boolean(), server_default=sa.text('true'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_login_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
    op.create_table('investigations',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('name', sa.Text(), nullable=False),
    sa.Column('authorization_note', sa.Text(), nullable=False),
    sa.Column('lawful_basis_confirmed', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('lawful_basis_confirmed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('analyst_assessment', sa.Text(), nullable=True),
    sa.Column('analyst_assessment_updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('owner_id', sa.UUID(), nullable=True),
    sa.Column('shared_with', sa.ARRAY(sa.UUID()), server_default=sa.text("'{}'::uuid[]"), nullable=False),
    sa.Column('watch_config', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('retention_days', sa.Integer(), server_default=sa.text('90'), nullable=False),
    sa.Column('permanently_active', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('disabled_tools', sa.ARRAY(sa.Text()), server_default=sa.text("'{}'::text[]"), nullable=False),
    sa.Column('last_reviewed_run_number', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint('lawful_basis_confirmed = true', name='ck_investigations_lawful_basis'),
    sa.CheckConstraint('length(btrim(authorization_note)) > 0', name='ck_investigations_authorization_note'),
    sa.CheckConstraint('retention_days > 0', name='ck_investigations_retention_positive'),
    sa.ForeignKeyConstraint(['owner_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_investigations_owner_id'), 'investigations', ['owner_id'], unique=False)
    op.create_table('access_log',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_id', sa.UUID(), nullable=True),
    sa.Column('user_id', sa.UUID(), nullable=True),
    sa.Column('action', sa.Text(), nullable=False),
    sa.Column('detail', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_access_log_case_id'), 'access_log', ['case_id'], unique=False)
    op.create_table('scan_runs',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_id', sa.UUID(), nullable=False),
    sa.Column('run_number', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=16), server_default=sa.text("'queued'"), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('tools_included', sa.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('tools_completed', sa.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('tools_failed', sa.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.Column('failure_details', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('jobs_total', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('jobs_done', sa.Integer(), server_default=sa.text('0'), nullable=False),
    sa.Column('triggered_by', sa.String(length=16), server_default=sa.text("'manual'"), nullable=False),
    sa.Column('priority', sa.Integer(), server_default=sa.text('10'), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.CheckConstraint("triggered_by IN ('manual', 'watch_mode', 'pivot_chain', 'health_check')", name='ck_scan_runs_triggered_by'),
    sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('case_id', 'run_number', name='uq_scan_runs_case_run')
    )
    op.create_index(op.f('ix_scan_runs_case_id'), 'scan_runs', ['case_id'], unique=False)
    op.create_table('targets',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_id', sa.UUID(), nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.Column('value_digest', sa.String(length=64), nullable=False),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('context_tags', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'[]'::jsonb"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_targets_case_id'), 'targets', ['case_id'], unique=False)
    op.create_table('entities',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_id', sa.UUID(), nullable=False),
    sa.Column('scan_run_id', sa.UUID(), nullable=True),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('value', sa.Text(), nullable=False),
    sa.Column('value_digest', sa.String(length=64), nullable=False),
    sa.Column('attributes', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('source_tool', sa.Text(), nullable=False),
    sa.Column('confidence', sa.Float(), server_default=sa.text('0'), nullable=False),
    sa.Column('field_confidence', postgresql.JSONB(astext_type=sa.Text()), server_default=sa.text("'{}'::jsonb"), nullable=False),
    sa.Column('source_reliability', sa.String(length=1), server_default=sa.text("'F'"), nullable=False),
    sa.Column('tag_match_score', sa.Float(), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('last_verified', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('confirmed_flag', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('is_seed', sa.Boolean(), server_default=sa.text('false'), nullable=False),
    sa.Column('merged_into_id', sa.UUID(), nullable=True),
    sa.CheckConstraint("source_reliability IN ('A','B','C','D','E','F')", name='ck_entities_source_reliability'),
    sa.CheckConstraint('confidence >= 0 AND confidence <= 1', name='ck_entities_confidence_range'),
    sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['merged_into_id'], ['entities.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['scan_run_id'], ['scan_runs.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_entities_case_id'), 'entities', ['case_id'], unique=False)
    op.create_index('ix_entities_case_type_digest', 'entities', ['case_id', 'type', 'value_digest'], unique=False)
    op.create_table('entity_observations',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('entity_id', sa.UUID(), nullable=False),
    sa.Column('scan_run_id', sa.UUID(), nullable=False),
    sa.Column('source_tool', sa.Text(), nullable=False),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('attributes_digest', sa.String(length=64), nullable=True),
    sa.Column('observed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['entity_id'], ['entities.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_run_id'], ['scan_runs.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('entity_id', 'scan_run_id', 'source_tool', name='uq_entity_observations')
    )
    op.create_index(op.f('ix_entity_observations_entity_id'), 'entity_observations', ['entity_id'], unique=False)
    op.create_index(op.f('ix_entity_observations_scan_run_id'), 'entity_observations', ['scan_run_id'], unique=False)
    op.create_table('pivot_log',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_id', sa.UUID(), nullable=False),
    sa.Column('scan_run_id', sa.UUID(), nullable=True),
    sa.Column('job_id', sa.Text(), nullable=True),
    sa.Column('triggering_entity_id', sa.UUID(), nullable=True),
    sa.Column('triggered_tool', sa.Text(), nullable=False),
    sa.Column('rule_matched', sa.Text(), nullable=False),
    sa.Column('confidence_at_trigger', sa.Float(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_run_id'], ['scan_runs.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['triggering_entity_id'], ['entities.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_pivot_log_case_id'), 'pivot_log', ['case_id'], unique=False)
    op.create_table('relations',
    sa.Column('id', sa.UUID(), server_default=sa.text('gen_random_uuid()'), nullable=False),
    sa.Column('case_id', sa.UUID(), nullable=False),
    sa.Column('entity_a_id', sa.UUID(), nullable=False),
    sa.Column('entity_b_id', sa.UUID(), nullable=False),
    sa.Column('relation_type', sa.Text(), nullable=False),
    sa.Column('source_tool', sa.Text(), nullable=False),
    sa.Column('match_explanation', sa.Text(), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('created_by', sa.Text(), server_default=sa.text("'engine'"), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['case_id'], ['investigations.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['entity_a_id'], ['entities.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['entity_b_id'], ['entities.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_relations_case_id'), 'relations', ['case_id'], unique=False)
    op.create_index(op.f('ix_relations_entity_a_id'), 'relations', ['entity_a_id'], unique=False)
    op.create_index(op.f('ix_relations_entity_b_id'), 'relations', ['entity_b_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_relations_entity_b_id'), table_name='relations')
    op.drop_index(op.f('ix_relations_entity_a_id'), table_name='relations')
    op.drop_index(op.f('ix_relations_case_id'), table_name='relations')
    op.drop_table('relations')
    op.drop_index(op.f('ix_pivot_log_case_id'), table_name='pivot_log')
    op.drop_table('pivot_log')
    op.drop_index(op.f('ix_entity_observations_scan_run_id'), table_name='entity_observations')
    op.drop_index(op.f('ix_entity_observations_entity_id'), table_name='entity_observations')
    op.drop_table('entity_observations')
    op.drop_index('ix_entities_case_type_digest', table_name='entities')
    op.drop_index(op.f('ix_entities_case_id'), table_name='entities')
    op.drop_table('entities')
    op.drop_index(op.f('ix_targets_case_id'), table_name='targets')
    op.drop_table('targets')
    op.drop_index(op.f('ix_scan_runs_case_id'), table_name='scan_runs')
    op.drop_table('scan_runs')
    op.drop_index(op.f('ix_access_log_case_id'), table_name='access_log')
    op.drop_table('access_log')
    op.drop_index(op.f('ix_investigations_owner_id'), table_name='investigations')
    op.drop_table('investigations')
    op.drop_table('users')
    op.drop_table('tool_config')
