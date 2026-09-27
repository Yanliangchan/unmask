"""Case (investigation) lifecycle and access control."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import any_, func, literal, or_, select
from sqlalchemy.dialects.postgresql import UUID, distinct_on
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app import crypto
from app.models import TARGET_TYPES, Entity, Investigation, ScanRun, Target, User

_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
_PHONE = re.compile(r"^\+?[0-9 ()\-.]{6,20}$")


class CaseValidationError(ValueError):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


@dataclass
class TargetInput:
    value: str
    type: str
    context_tags: list[str] = field(default_factory=list)


def parse_tags(raw: str | list[str] | None) -> list[str]:
    if raw is None:
        return []
    items = raw if isinstance(raw, list) else raw.split(",")
    seen: list[str] = []
    for item in items:
        tag = item.strip()[:64]
        if tag and tag.lower() not in (t.lower() for t in seen):
            seen.append(tag)
    return seen[:20]


def validate_target(t: TargetInput) -> str | None:
    value = t.value.strip()
    if not value:
        return None
    if t.type not in TARGET_TYPES:
        return f"Unknown target type '{t.type}'"
    if t.type == "email" and not _EMAIL.match(value):
        return f"'{value}' is not a valid email address"
    if t.type == "domain" and not _DOMAIN.match(value):
        return f"'{value}' is not a valid domain"
    if t.type == "phone" and not _PHONE.match(value):
        return f"'{value}' is not a valid phone number"
    if len(value) > 512:
        return "Target values are limited to 512 characters"
    return None


async def create_case(
    session: AsyncSession,
    *,
    owner: User,
    name: str,
    authorization_note: str,
    lawful_basis_confirmed: bool,
    targets: list[TargetInput],
    disabled_tools: list[str],
    notes: str | None = None,
) -> Investigation:
    errors: list[str] = []
    if not name.strip():
        errors.append("Case name is required")
    if not authorization_note.strip():
        errors.append("An authorization note is required")
    if not lawful_basis_confirmed:
        errors.append("You must confirm a lawful basis before creating a case")
    real_targets = [t for t in targets if t.value.strip()]
    if not real_targets:
        errors.append("Add at least one target")
    errors.extend(e for t in real_targets if (e := validate_target(t)))
    if errors:
        raise CaseValidationError(errors)

    now = datetime.now(UTC)
    case = Investigation(
        name=name.strip()[:200],
        authorization_note=authorization_note.strip(),
        lawful_basis_confirmed=True,
        lawful_basis_confirmed_at=now,
        notes=(notes or "").strip() or None,
        owner_id=owner.id,
        shared_with=[],
        watch_config={"enabled": False},
        disabled_tools=sorted(set(disabled_tools)),
    )
    session.add(case)
    await session.flush()
    for t in real_targets:
        value = t.value.strip()
        digest = crypto.digest(t.type, value)
        session.add(Target(case_id=case.id, value=value, value_digest=digest, type=t.type, context_tags=t.context_tags))
        # The target itself is the seed node every discovery hangs off.
        session.add(
            Entity(
                case_id=case.id,
                type=t.type,
                value=value,
                value_digest=digest,
                attributes={"origin": "analyst-supplied target", "context_tags": t.context_tags},
                source_tool="analyst",
                confidence=1.0,
                field_confidence={"value": 1.0},
                source_reliability="A",
                is_seed=True,
            )
        )
    await session.flush()
    return case


def _visible_to(user: User):
    return or_(
        Investigation.owner_id == user.id, literal(user.id, UUID(as_uuid=True)) == any_(Investigation.shared_with)
    )


async def get_case_for_user(session: AsyncSession, case_id: uuid.UUID, user: User) -> Investigation:
    case = await session.scalar(
        select(Investigation)
        .where(Investigation.id == case_id, _visible_to(user))
        .options(selectinload(Investigation.targets), selectinload(Investigation.scan_runs))
    )
    if case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case


@dataclass
class CaseCard:
    case: Investigation
    target_count: int
    last_scan_at: datetime | None
    last_scan_status: str | None
    new_count: int
    purge_at: datetime | None = None

    @property
    def purge_soon(self) -> bool:
        from app.scheduler import PURGE_WARNING_DAYS

        return self.purge_at is not None and (self.purge_at - datetime.now(UTC)).days < PURGE_WARNING_DAYS

    @property
    def watch_active(self) -> bool:
        return bool((self.case.watch_config or {}).get("enabled"))


async def list_cases_for_user(session: AsyncSession, user: User) -> list[CaseCard]:
    cases = (
        await session.scalars(select(Investigation).where(_visible_to(user)).order_by(Investigation.created_at.desc()))
    ).all()
    if not cases:
        return []
    ids = [c.id for c in cases]
    target_counts = dict(
        (
            await session.execute(
                select(Target.case_id, func.count()).where(Target.case_id.in_(ids)).group_by(Target.case_id)
            )
        ).all()
    )
    # Only the latest run per case (Postgres DISTINCT ON), not every run ever made.
    last_runs: dict[uuid.UUID, ScanRun] = {
        run.case_id: run
        for run in (
            await session.scalars(
                select(ScanRun)
                .where(ScanRun.case_id.in_(ids))
                .order_by(ScanRun.case_id, ScanRun.run_number.desc())
                .ext(distinct_on(ScanRun.case_id))
            )
        ).all()
    }
    new_rows = (
        await session.execute(
            select(Entity.case_id, func.count())
            .join(ScanRun, Entity.scan_run_id == ScanRun.id)
            .join(Investigation, Investigation.id == Entity.case_id)
            .where(
                Entity.case_id.in_(ids),
                Entity.merged_into_id.is_(None),
                ScanRun.run_number > Investigation.last_reviewed_run_number,
            )
            .group_by(Entity.case_id)
        )
    ).all()
    new_counts = dict(new_rows)
    from app.scheduler import last_scan_times, purge_date_from

    last_scans = await last_scan_times(session, ids)

    cards = []
    for c in cases:
        run = last_runs.get(c.id)
        cards.append(
            CaseCard(
                case=c,
                target_count=target_counts.get(c.id, 0),
                last_scan_at=(run.completed_at or run.started_at or run.created_at) if run else None,
                last_scan_status=run.status if run else None,
                new_count=new_counts.get(c.id, 0),
                purge_at=purge_date_from(c, last_scans.get(c.id)),
            )
        )
    return cards


async def mark_reviewed(session: AsyncSession, case: Investigation) -> None:
    latest = max((r.run_number for r in case.scan_runs if r.status in ("completed", "partial", "failed")), default=0)
    if latest > case.last_reviewed_run_number:
        case.last_reviewed_run_number = latest


async def delete_case(session: AsyncSession, case_id: uuid.UUID, *, user_id: uuid.UUID | None, action: str, **detail):
    """Delete a case and everything in it, keeping its audit trail readable.

    access_log.case_id is nulled by the delete, so the case id is first copied
    into each audit row's detail; then the final audit row is written.
    """
    from sqlalchemy import delete, text, update

    from app.models import AccessLog

    await session.execute(
        update(AccessLog)
        .where(AccessLog.case_id == case_id)
        .values(detail=AccessLog.detail.op("||")(text("jsonb_build_object('case_id', CAST(:cid AS text))")))
        .execution_options(synchronize_session=False),
        {"cid": str(case_id)},
    )
    session.add(AccessLog(case_id=None, user_id=user_id, action=action, detail={"case_id": str(case_id), **detail}))
    await session.execute(delete(Investigation).where(Investigation.id == case_id))
