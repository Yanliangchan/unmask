"""Search across every case a user can see: case names, targets and findings.

Identifiers are encrypted at rest, so matching happens after decryption,
limited to the user's own and shared cases. "Where else have we seen this
email?" is the question this answers.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Entity, Investigation, User
from app.services.cases import visible_case_ids

MIN_QUERY = 2


@dataclass
class Hit:
    group: str  # "Cases" | "Targets" | "Findings"
    label: str
    hint: str
    url: str


def _match(q: str, text: str) -> bool:
    return q in (text or "").casefold()


async def global_search(session: AsyncSession, user: User, q: str, limit: int = 30) -> list[Hit]:
    q = q.strip().casefold()
    if len(q) < MIN_QUERY:
        return []
    ids = await visible_case_ids(session, user)
    if not ids:
        return []
    cases = {c.id: c for c in (await session.scalars(select(Investigation).where(Investigation.id.in_(ids)))).all()}
    hits: list[Hit] = []
    for c in sorted(cases.values(), key=lambda c: c.created_at, reverse=True):
        if _match(q, c.name):
            hits.append(Hit("Cases", c.name, f"case · created {c.created_at:%d %b %Y}", f"/cases/{c.id}"))
    entities = (
        await session.scalars(
            select(Entity).where(
                Entity.case_id.in_(ids), Entity.merged_into_id.is_(None), Entity.dismissed_flag.is_(False)
            )
        )
    ).all()
    targets, findings = [], []
    for e in entities:
        if not _match(q, e.value):
            continue
        case = cases.get(e.case_id)
        hint = f"{e.type.replace('_', ' ')} · {case.name if case else 'case'}"
        hit = Hit("Targets" if e.is_seed else "Findings", e.value, hint, f"/cases/{e.case_id}#ent-{e.id}")
        (targets if e.is_seed else findings).append((e, hit))
    findings.sort(key=lambda pair: (not pair[0].confirmed_flag, -pair[0].confidence))
    hits += [h for _, h in targets] + [h for _, h in findings]
    return hits[:limit]
