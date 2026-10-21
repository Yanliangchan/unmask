"""Source reliability over time: how each tool has actually behaved in the cases you can see.

Counted from what scans already record (which tools ran, finished or failed, and why) and
from analyst decisions. These are operational facts, not a precision score: a tool whose
findings analysts keep may simply be one they only review when it looks right, and a high
failure rate can be the sites' doing (bot walls from cloud servers), not the tool's.
"""

from __future__ import annotations

import re
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Entity, EntityObservation, ScanRun

WINDOW_DAYS = 30
_BLOCKED = re.compile(r"block|bot|captcha|rate.?limit|429|403|forbidden|too many|cloudflare|proxy", re.I)


@dataclass
class SourceStats:
    tool: str
    runs: int = 0
    completed: int = 0
    failed: int = 0
    blocked: int = 0
    findings: int = 0
    kept: int = 0
    ruled_out: int = 0
    last_failure: str | None = None
    last_failure_at: datetime | None = None

    @property
    def success_rate(self) -> float | None:
        done = self.completed + self.failed
        return self.completed / done if done else None

    @property
    def decided(self) -> int:
        return self.kept + self.ruled_out


async def source_stats(
    session: AsyncSession, case_ids: list[uuid.UUID], days: int = WINDOW_DAYS
) -> dict[str, SourceStats]:
    since = datetime.now(UTC) - timedelta(days=days)
    stats: dict[str, SourceStats] = defaultdict(lambda: SourceStats(""))
    if not case_ids:
        return {}

    def get(tool: str) -> SourceStats:
        s = stats[tool]
        s.tool = tool
        return s

    runs = (
        await session.scalars(
            select(ScanRun).where(
                ScanRun.case_id.in_(case_ids), ScanRun.created_at >= since, ScanRun.triggered_by != "health_check"
            )  # fmt: skip
        )
    ).all()
    for run in runs:
        details = run.failure_details or {}
        for tool in run.tools_included or []:
            s = get(tool)
            s.runs += 1
            if tool in (run.tools_completed or []):
                s.completed += 1
            elif tool in (run.tools_failed or []):
                s.failed += 1
                reason = str(details.get(tool) or "")
                if _BLOCKED.search(reason):
                    s.blocked += 1
                when = run.completed_at or run.created_at
                if s.last_failure_at is None or when > s.last_failure_at:
                    s.last_failure, s.last_failure_at = reason[:200] or None, when

    found = await session.execute(
        select(EntityObservation.source_tool, func.count(func.distinct(EntityObservation.entity_id)))
        .join(Entity, Entity.id == EntityObservation.entity_id)
        .where(Entity.case_id.in_(case_ids), EntityObservation.observed_at >= since)
        .group_by(EntityObservation.source_tool)
    )
    for tool, n in found:
        get(tool).findings = n

    decisions = await session.execute(
        select(Entity.source_tool, Entity.confirmed_flag, Entity.dismissed_flag, func.count(Entity.id))
        .where(Entity.case_id.in_(case_ids), Entity.is_seed.is_(False),
               (Entity.confirmed_flag.is_(True)) | (Entity.dismissed_flag.is_(True)))
        .group_by(Entity.source_tool, Entity.confirmed_flag, Entity.dismissed_flag)
    )  # fmt: skip
    for tool, confirmed, dismissed, n in decisions:
        s = get(tool)
        if confirmed:
            s.kept += n
        elif dismissed:
            s.ruled_out += n
    return {k: v for k, v in stats.items() if k not in ("analyst", "correlation")}
