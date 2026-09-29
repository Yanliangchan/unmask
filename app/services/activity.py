"""A case's activity feed: who did what, and when, in plain words.

Built from the audit log (every decision is already recorded there), notes
and scan runs. Opening a case is audited too, but it isn't activity, so it
is left out of the feed; the full audit trail stays in the database.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AccessLog, Entity, Note, ScanRun, User
from app.services.accuracy import DISMISS_REASONS
from app.services.templates import BY_KEY as TEMPLATES

# Audit actions that aren't activity.
QUIET = {"view_case", "view_pivot_log", "login", "logout", "login_failed", "login_blocked"}


@dataclass
class Event:
    at: datetime
    actor: str  # an analyst's email, or "unmask" for the system
    text: str
    icon: str = "note"
    url: str | None = None
    entity: str | None = None  # the finding it concerns, if any
    quote: str | None = None  # a note's text


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'s' if n != 1 else ''}"


def _describe(row: AccessLog) -> tuple[str, str] | None:
    """(text, icon) for an audit row, or None to leave it out."""
    d = row.detail or {}
    a = row.action
    if a in QUIET:
        return None
    reason = DISMISS_REASONS.get(d.get("reason") or "", "")
    table = {
        "create_case": ("created the case" + (f" from the {TEMPLATES[d['template']].label} template"
                        if d.get("template") in TEMPLATES else ""), "folder"),
        "run_scan": (f"started scan {d.get('run_number', '')}".strip(), "refresh"),
        "cancel_scan": ("stopped a scan", "x"),
        "confirm_entity": ("confirmed a finding", "check"),
        "unconfirm_entity": ("took back a confirmation", "x"),
        "dismiss_entity": ("ruled out a finding" + (f": {reason.lower()}" if reason else ""), "x"),
        "restore_entity": ("restored a finding", "refresh"),
        "bulk_confirm": (f"confirmed {_plural(d.get('count', 0), 'finding')} at once", "check"),
        "bulk_unconfirm": (f"took back {_plural(d.get('count', 0), 'confirmation')}", "x"),
        "bulk_dismiss": (f"ruled out {_plural(d.get('count', 0), 'finding')} at once", "x"),
        "bulk_restore": (f"restored {_plural(d.get('count', 0), 'finding')}", "refresh"),
        "merge_entities": ("merged two findings as the same thing", "merge"),
        "split_entity": ("split a merged finding apart", "merge"),
        "accept_suggestion": ("accepted a suggested duplicate", "merge"),
        "dismiss_suggestion": ("rejected a suggested duplicate", "x"),
        "run_correlation": ("re-ran matching", "refresh"),
        "add_finding": ("added a finding by hand", "plus"),
        "add_note": (None, "note"),  # shown from the note itself
        "share_case": ("shared the case with a colleague", "link"),
        "unshare_case": ("stopped sharing the case with a colleague", "link"),
        "watch_on": (f"turned on watch mode ({d.get('frequency', 'weekly')})", "bell"),
        "watch_off": ("turned off watch mode", "bell"),
        "watch_settings": ("changed watch mode settings", "bell"),
        "retention_settings": ("changed how long the case is kept", "shield"),
        "auto_pivot_on": ("turned on automatic follow-ups", "refresh"),
        "auto_pivot_off": ("turned off automatic follow-ups", "refresh"),
        "analyst_assessment": ("updated the assessment", "note"),
        "export_report": ("exported the report", "download"),
    }  # fmt: skip
    text, icon = table.get(a, (a.replace("_", " "), "note"))
    return (text, icon) if text else None


async def case_activity(session: AsyncSession, case_id: uuid.UUID, limit: int = 200) -> list[Event]:
    logs = (
        await session.scalars(
            select(AccessLog)
            .where(AccessLog.case_id == case_id, AccessLog.action.not_in(QUIET))
            .order_by(AccessLog.timestamp.desc())
            .limit(limit)
        )
    ).all()
    notes = (
        await session.scalars(select(Note).where(Note.case_id == case_id).order_by(Note.created_at.desc()).limit(limit))
    ).all()
    runs = (
        await session.scalars(
            select(ScanRun)
            .where(ScanRun.case_id == case_id, ScanRun.completed_at.is_not(None))
            .order_by(ScanRun.run_number.desc())
            .limit(limit)
        )
    ).all()
    user_ids = {r.user_id for r in logs if r.user_id} | {n.author_id for n in notes if n.author_id}
    users = {u.id: u.email for u in (await session.scalars(select(User).where(User.id.in_(user_ids)))).all()}
    entity_ids = {uuid.UUID(r.detail["entity_id"]) for r in logs if (r.detail or {}).get("entity_id")}
    entity_ids |= {n.entity_id for n in notes if n.entity_id}
    values: dict[uuid.UUID, str] = {}
    if entity_ids:
        found = await session.scalars(select(Entity).where(Entity.case_id == case_id, Entity.id.in_(entity_ids)))
        values = {e.id: e.value for e in found.all()}

    events: list[Event] = []
    for r in logs:
        described = _describe(r)
        if described is None:
            continue
        eid = (r.detail or {}).get("entity_id")
        entity = values.get(uuid.UUID(eid)) if eid else None
        actor = users.get(r.user_id, "Former user") if r.user_id else "unmask"
        url = f"/cases/{case_id}#ent-{eid}" if entity else None
        events.append(Event(r.timestamp, actor, described[0], described[1], url, entity))
    for n in notes:
        entity = values.get(n.entity_id) if n.entity_id else None
        url = f"/cases/{case_id}#ent-{n.entity_id}" if entity else None
        events.append(
            Event(n.created_at, users.get(n.author_id, "Former user"), "added a note", "note", url, entity, n.body)
        )
    for run in runs:
        who = {"watch_mode": "Watch mode", "pivot_chain": "Follow-up"}.get(run.triggered_by, "Scan")
        failed = f", {_plural(len(run.tools_failed), 'tool')} failed" if run.tools_failed else ""
        events.append(Event(run.completed_at, "unmask", f"{who} {run.run_number} finished ({run.status}){failed}",
                            "refresh", f"/cases/{case_id}/timeline?b={run.run_number}"))  # fmt: skip
    events.sort(key=lambda e: e.at, reverse=True)
    return events[:limit]
