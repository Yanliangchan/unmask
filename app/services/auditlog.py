"""The audit log as rows for export (CSV for people, JSON Lines for a SIEM)."""

from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AccessLog, User

FIELDS = ("timestamp", "action", "user", "case_id", "ip", "detail")


async def audit_rows(session: AsyncSession, *, days: int = 30, since: datetime | None = None,
                     limit: int | None = None) -> list[dict]:  # fmt: skip
    start = since or datetime.now(UTC) - timedelta(days=days)
    q = (
        select(AccessLog, User.email)
        .outerjoin(User, User.id == AccessLog.user_id)
        .where(AccessLog.timestamp >= start)
        .order_by(AccessLog.timestamp)
    )
    if limit:
        q = q.limit(limit)
    return [
        {"timestamp": a.timestamp.isoformat(), "action": a.action, "user": email,
         "case_id": str(a.case_id) if a.case_id else None, "ip": a.ip, "detail": a.detail, "id": str(a.id)}
        for a, email in (await session.execute(q)).all()
    ]  # fmt: skip


def _cell(value) -> str:
    if isinstance(value, dict | list):
        text = json.dumps(value, sort_keys=True)
    else:
        text = "" if value is None else str(value)
    # Spreadsheet formula injection: a cell starting with = + - @ is shown as text.
    return "'" + text if text[:1] in ("=", "+", "-", "@") else text


def to_csv(rows: list[dict]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(FIELDS)
    for r in rows:
        w.writerow([_cell(r[f]) for f in FIELDS])
    return "\ufeff" + buf.getvalue()


def to_jsonl(rows: list[dict]) -> str:
    return "".join(json.dumps(r, sort_keys=True, default=str) + "\n" for r in rows)
