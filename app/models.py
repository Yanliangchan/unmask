"""Database schema.

The full schema is defined up front (Phase 0) so later phases never need to
partially migrate existing case data.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    ARRAY,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app import crypto
from app.db import Base


class EncryptedText(TypeDecorator):
    """Text column that is transparently encrypted at rest."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else crypto.encrypt(value)

    def process_result_value(self, value, dialect):
        return None if value is None else crypto.decrypt(value)


class EncryptedJSON(TypeDecorator):
    """JSONB column whose payload is encrypted as a single opaque blob."""

    impl = JSONB
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return None if value is None else crypto.encrypt_json(value)

    def process_result_value(self, value, dialect):
        return None if value is None else crypto.decrypt_json(value)


def _uuid_pk() -> Mapped[uuid.UUID]:
    return mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, server_default=text("gen_random_uuid()")
    )


def _now() -> Mapped[datetime]:
    return mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


# Source reliability uses the Admiralty (NATO) scale. It rates trust in the
# *source class* and is deliberately independent of `confidence`, which rates
# whether an entity belongs to the subject.
SOURCE_RELIABILITY = {
    "A": "Completely reliable",
    "B": "Usually reliable",
    "C": "Fairly reliable",
    "D": "Not usually reliable",
    "E": "Unreliable",
    "F": "Reliability cannot be judged",
}

TARGET_TYPES = ["username", "email", "domain", "phone", "ip", "name", "image"]


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = _uuid_pk()
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(200))
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    created_at: Mapped[datetime] = _now()
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Notification channels and small UI choices (onboarding dismissed, ...).
    preferences: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    # Incoming-webhook URL for Slack (or a compatible service). It is a credential, so encrypted.
    slack_webhook: Mapped[str | None] = mapped_column(EncryptedText)


class Investigation(Base):
    __tablename__ = "investigations"
    __table_args__ = (
        # Hard block at the database layer, not just in the form.
        CheckConstraint("lawful_basis_confirmed = true", name="ck_investigations_lawful_basis"),
        CheckConstraint("length(btrim(authorization_note)) > 0", name="ck_investigations_authorization_note"),
        CheckConstraint("retention_days > 0", name="ck_investigations_retention_positive"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    name: Mapped[str] = mapped_column(Text, nullable=False)
    authorization_note: Mapped[str] = mapped_column(Text, nullable=False)
    lawful_basis_confirmed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    lawful_basis_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    notes: Mapped[str | None] = mapped_column(Text)
    # Human-written conclusion; required before a report can be exported.
    analyst_assessment: Mapped[str | None] = mapped_column(Text)
    analyst_assessment_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    owner_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    shared_with: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(UUID(as_uuid=True)), nullable=False, server_default=text("'{}'::uuid[]")
    )
    watch_config: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("90"))
    permanently_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    disabled_tools: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'::text[]"))
    last_reviewed_run_number: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    # Built from made-up data to show how the app works; it can't be scanned.
    is_sample: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    # Which case template it started from, if any.
    template: Mapped[str | None] = mapped_column(String(40))
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )

    targets: Mapped[list[Target]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", order_by="Target.created_at"
    )
    scan_runs: Mapped[list[ScanRun]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan", order_by="ScanRun.run_number"
    )


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    value: Mapped[str] = mapped_column(EncryptedText, nullable=False)
    value_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    context_tags: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    created_at: Mapped[datetime] = _now()

    investigation: Mapped[Investigation] = relationship(back_populates="targets")


class ScanRun(Base):
    __tablename__ = "scan_runs"
    __table_args__ = (
        UniqueConstraint("case_id", "run_number", name="uq_scan_runs_case_run"),
        CheckConstraint(
            "triggered_by IN ('manual', 'watch_mode', 'pivot_chain', 'health_check')",
            name="ck_scan_runs_triggered_by",
        ),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    run_number: Mapped[int] = mapped_column(Integer, nullable=False)
    # queued | running | completed | partial | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'queued'"))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tools_included: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    tools_completed: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    tools_failed: Mapped[list[str]] = mapped_column(ARRAY(Text), nullable=False, server_default=text("'{}'"))
    # {"tool_name": "reason"} — every failure is recorded, never swallowed.
    # Keys starting with "_" are run-level notes (e.g. "_correlation" summary).
    failure_details: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    jobs_total: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    jobs_done: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    triggered_by: Mapped[str] = mapped_column(String(16), nullable=False, server_default=text("'manual'"))
    # Lower number = higher priority; manual scans preempt watch-mode jobs.
    priority: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("10"))
    created_at: Mapped[datetime] = _now()

    investigation: Mapped[Investigation] = relationship(back_populates="scan_runs")


class Entity(Base):
    __tablename__ = "entities"
    __table_args__ = (
        Index("ix_entities_case_type_digest", "case_id", "type", "value_digest"),
        CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_entities_confidence_range"),
        CheckConstraint("source_reliability IN ('A','B','C','D','E','F')", name="ck_entities_source_reliability"),
    )

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"), index=True)
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    value: Mapped[str] = mapped_column(EncryptedText, nullable=False)
    value_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    attributes: Mapped[dict[str, Any]] = mapped_column(EncryptedJSON, nullable=False, default=dict)
    source_tool: Mapped[str] = mapped_column(Text, nullable=False)
    # "Is this the same person?" — produced by correlation.
    confidence: Mapped[float] = mapped_column(Float, nullable=False, server_default=text("0"))
    field_confidence: Mapped[dict[str, float]] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb")
    )
    # "How much do we trust this class of source?" — Admiralty A–F.
    source_reliability: Mapped[str] = mapped_column(String(1), nullable=False, server_default=text("'F'"))
    tag_match_score: Mapped[float | None] = mapped_column(Float)
    first_seen: Mapped[datetime] = _now()
    last_verified: Mapped[datetime] = _now()
    confirmed_flag: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    # An analyst said "not them": hidden from views and reports, kept for the record.
    dismissed_flag: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    # Account hits only: verified | unverified (see app/verify.py). Null for other types.
    verification: Mapped[str | None] = mapped_column(String(12))
    # Accounts only: the site's host ("github.com"), kept in clear so decisions can be
    # counted per site (app/services/accuracy.py). A site name is not personal data.
    site_host: Mapped[str | None] = mapped_column(String(255), index=True)
    # Why the analyst said "Not them": different_person | not_a_profile | bot_or_spam | other
    dismiss_reason: Mapped[str | None] = mapped_column(String(32))
    is_seed: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    merged_into_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("entities.id", ondelete="SET NULL"), index=True)

    observations: Mapped[list[EntityObservation]] = relationship(
        back_populates="entity", cascade="all, delete-orphan", order_by="EntityObservation.observed_at"
    )


class EntityObservation(Base):
    """One sighting of an entity by one tool in one scan run (drives diffing)."""

    __tablename__ = "entity_observations"
    __table_args__ = (UniqueConstraint("entity_id", "scan_run_id", "source_tool", name="uq_entity_observations"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    entity_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    source_tool: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float | None] = mapped_column(Float)
    attributes_digest: Mapped[str | None] = mapped_column(String(64))
    observed_at: Mapped[datetime] = _now()

    entity: Mapped[Entity] = relationship(back_populates="observations")


class Relation(Base):
    __tablename__ = "relations"

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_a_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_b_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("entities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relation_type: Mapped[str] = mapped_column(Text, nullable=False)
    source_tool: Mapped[str] = mapped_column(Text, nullable=False)
    # Explanations quote the values they compare, so they are encrypted too.
    match_explanation: Mapped[str | None] = mapped_column(EncryptedText)
    confidence: Mapped[float | None] = mapped_column(Float)
    created_by: Mapped[str] = mapped_column(Text, nullable=False, server_default=text("'engine'"))
    created_at: Mapped[datetime] = _now()


class PivotLog(Base):
    __tablename__ = "pivot_log"

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scan_runs.id", ondelete="SET NULL"), index=True)
    job_id: Mapped[str | None] = mapped_column(Text)
    triggering_entity_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("entities.id", ondelete="SET NULL"), index=True
    )
    triggered_tool: Mapped[str] = mapped_column(Text, nullable=False)
    rule_matched: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_at_trigger: Mapped[float | None] = mapped_column(Float)
    created_at: Mapped[datetime] = _now()


class ToolConfig(Base):
    __tablename__ = "tool_config"

    tool_name: Mapped[str] = mapped_column(Text, primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("true"))
    max_concurrent: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("3"))
    delay_between_requests_ms: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("500"))
    consecutive_failures: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    # Set when the circuit breaker (not a human) disabled the tool.
    circuit_open: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_reason: Mapped[str | None] = mapped_column(Text)
    last_health_check_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_health_ok: Mapped[bool | None] = mapped_column(Boolean)


class AccessLog(Base):
    __tablename__ = "access_log"

    id: Mapped[uuid.UUID] = _uuid_pk()
    # SET NULL so the audit trail survives case deletion.
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("investigations.id", ondelete="SET NULL"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    ip: Mapped[str | None] = mapped_column(String(64))
    timestamp: Mapped[datetime] = _now()


class SavedView(Base):
    """A named set of entity filters, saved by one analyst for one case."""

    __tablename__ = "saved_views"
    __table_args__ = (UniqueConstraint("case_id", "user_id", "name", name="uq_saved_views_name"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = _now()


class Note(Base):
    """An analyst's note on a finding. The text is case content, so it is encrypted."""

    __tablename__ = "notes"

    id: Mapped[uuid.UUID] = _uuid_pk()
    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    entity_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("entities.id", ondelete="CASCADE"), index=True)
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    body: Mapped[str] = mapped_column(EncryptedText, nullable=False)
    # Users @mentioned in the note (ids), for notifications.
    mentions: Mapped[list[str]] = mapped_column(JSONB, nullable=False, server_default=text("'[]'::jsonb"))
    created_at: Mapped[datetime] = _now()


class Notification(Base):
    """Something a user should know about: a scan finished, a mention, a watched case changed."""

    __tablename__ = "notifications"
    __table_args__ = (Index("ix_notifications_user_unread", "user_id", "read_at"),)

    id: Mapped[uuid.UUID] = _uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    # scan_finished | watch_changes | mention | review_ready
    kind: Mapped[str] = mapped_column(String(32), nullable=False)
    # Written without identifiers ("3 new findings in <case>"), but encrypted anyway.
    text: Mapped[str] = mapped_column(EncryptedText, nullable=False)
    url: Mapped[str | None] = mapped_column(Text)
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()
