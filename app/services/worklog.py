"""The case working log: the analyst's running narrative, and the findings and links they pinned.

Log entries and pins are notes (``kind`` "log" and "pin"), so they are encrypted like any
note. The log is where reasoning accumulates while working; the assessment is the
conclusion. ``draft_assessment`` turns the log into a starting point for that conclusion:
it lays out the pinned evidence and the notes in order, and leaves the conclusion itself
for the analyst to write. It never decides anything.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Entity, Investigation, Note, Relation, User

MAX_BODY = 4000
MAX_WHY = 500


@dataclass
class Pin:
    note: Note
    entity: Entity | None = None
    relation: Relation | None = None
    ends: tuple[Entity | None, Entity | None] = (None, None)

    @property
    def gone(self) -> bool:
        """The finding it points at was merged away; the pin still says what it was."""
        return self.entity is not None and self.entity.merged_into_id is not None


@dataclass
class WorkLog:
    pins: list[Pin] = field(default_factory=list)
    entries: list[Note] = field(default_factory=list)
    authors: dict[uuid.UUID, str] = field(default_factory=dict)


async def worklog(session: AsyncSession, case_id: uuid.UUID) -> WorkLog:
    notes = (
        await session.scalars(
            select(Note).where(Note.case_id == case_id, Note.kind.in_(("log", "pin"))).order_by(Note.created_at)
        )
    ).all()
    pins = [n for n in notes if n.kind == "pin"]
    rel_ids = {n.relation_id for n in pins if n.relation_id}
    relations = {r.id: r for r in (await session.scalars(select(Relation).where(Relation.id.in_(rel_ids)))).all()}
    ent_ids = {n.entity_id for n in pins if n.entity_id}
    ent_ids |= {i for r in relations.values() for i in (r.entity_a_id, r.entity_b_id)}
    entities = {e.id: e for e in (await session.scalars(select(Entity).where(Entity.id.in_(ent_ids)))).all()}
    author_ids = {n.author_id for n in notes if n.author_id}
    authors = {u.id: u.email for u in (await session.scalars(select(User).where(User.id.in_(author_ids)))).all()}
    out = WorkLog(authors=authors, entries=[n for n in notes if n.kind == "log"])
    for n in pins:
        rel = relations.get(n.relation_id) if n.relation_id else None
        ends = (entities.get(rel.entity_a_id), entities.get(rel.entity_b_id)) if rel else (None, None)
        out.pins.append(Pin(n, entities.get(n.entity_id) if n.entity_id else None, rel, ends))
    return out


async def existing_pin(session: AsyncSession, case_id: uuid.UUID, *, entity_id=None, relation_id=None) -> Note | None:
    where = [Note.case_id == case_id, Note.kind == "pin"]
    where.append(Note.entity_id == entity_id if entity_id else Note.relation_id == relation_id)
    return await session.scalar(select(Note).where(*where).limit(1))


def _finding_line(e: Entity) -> str:
    state = "target" if e.is_seed else "confirmed" if e.confirmed_flag else "ruled out" if e.dismissed_flag else None
    score = f"score {e.confidence:.2f}" + (f", {state}" if state else "")
    return f"{e.type.replace('_', ' ')} {e.value} ({score})"


def _link_line(r: Relation, a: Entity | None, b: Entity | None) -> str:
    arrow = "→" if r.directed else "—"
    name = r.relation_type.replace("_", " ")
    return f"{a.value if a else '?'} {arrow} {b.value if b else '?'}: {name}, {r.basis}" + (
        f" ({r.match_explanation})" if r.match_explanation else ""
    )


def _when(dt: datetime) -> str:
    return dt.strftime("%-d %b %H:%M")


async def draft_assessment(session: AsyncSession, case: Investigation) -> str | None:
    """A draft for the analyst to edit, laid out from the working log. None if the log is empty."""
    log = await worklog(session, case.id)
    if not log.pins and not log.entries:
        return None
    lines = ["Conclusion: [what the evidence supports, and how strongly]", ""]
    findings = [p for p in log.pins if p.entity is not None]
    links = [p for p in log.pins if p.relation is not None]
    if findings:
        lines.append("Key findings:")
        for p in findings:
            lines.append(f"- {_finding_line(p.entity)}" + (f" — {p.note.body}" if p.note.body else ""))
        lines.append("")
    if links:
        lines.append("Key links:")
        for p in links:
            lines.append(f"- {_link_line(p.relation, *p.ends)}" + (f" — {p.note.body}" if p.note.body else ""))
        if any(p.relation.basis in ("rule", "similarity") for p in links):
            lines.append("  (Links by rule or similarity connect values, not people.)")
        lines.append("")
    if log.entries:
        lines.append("From the working log:")
        lines += [f"- {_when(n.created_at)}: {' '.join(n.body.split())}" for n in log.entries]
        lines.append("")
    lines += ["Still uncertain: [what would change this conclusion]", "Ruled out: [what you excluded, and why]"]
    return "\n".join(lines)[:20000]
