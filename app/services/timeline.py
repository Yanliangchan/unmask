"""Scan-to-scan diffing.

Works on observations (which tool saw which entity in which run), so a diff
is exact even after entities are merged. A value that "disappeared" because
the tool that found it failed or didn't run is labelled as such — it is not
reported as a real disappearance.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Entity, EntityObservation, ScanRun


@dataclass
class DiffItem:
    entity: Entity
    tools: list[str]
    note: str | None = None
    real: bool = True  # False when the disappearance is explained by a tool failure


@dataclass
class RunDiff:
    run_a: ScanRun
    run_b: ScanRun
    new: list[DiffItem] = field(default_factory=list)
    changed: list[DiffItem] = field(default_factory=list)
    gone: list[DiffItem] = field(default_factory=list)


def default_pair(runs: list[ScanRun]) -> tuple[ScanRun | None, ScanRun | None]:
    """Latest two comparable runs: analyst or watch-mode scans, not pivot chains."""
    comparable = [r for r in runs if r.triggered_by != "pivot_chain" and r.status != "queued"]
    comparable.sort(key=lambda r: r.run_number)
    if len(comparable) >= 2:
        return comparable[-2], comparable[-1]
    return (comparable[0] if comparable else None), None


async def _observed(session: AsyncSession, run_id: uuid.UUID, owner: dict) -> dict[uuid.UUID, dict[str, str]]:
    """owner entity -> {tool: attributes digest} for one run."""
    seen: dict[uuid.UUID, dict[str, str]] = defaultdict(dict)
    rows = await session.execute(
        select(EntityObservation.entity_id, EntityObservation.source_tool, EntityObservation.attributes_digest).where(
            EntityObservation.scan_run_id == run_id
        )
    )
    for entity_id, tool, digest in rows.all():
        if entity_id in owner:
            seen[owner[entity_id]][tool] = digest or ""
    return seen


async def diff_runs(session: AsyncSession, case_id: uuid.UUID, run_a: ScanRun, run_b: ScanRun) -> RunDiff:
    entities = (await session.scalars(select(Entity).where(Entity.case_id == case_id))).all()
    owner = {e.id: (e.merged_into_id or e.id) for e in entities}
    by_id = {e.id: e for e in entities}
    seen_a = await _observed(session, run_a.id, owner)
    seen_b = await _observed(session, run_b.id, owner)
    diff = RunDiff(run_a, run_b)

    for eid in seen_b.keys() - seen_a.keys():
        diff.new.append(DiffItem(by_id[eid], sorted(seen_b[eid])))

    for eid in seen_a.keys() & seen_b.keys():
        changed = sorted(t for t in seen_a[eid].keys() & seen_b[eid].keys() if seen_a[eid][t] != seen_b[eid][t])
        if changed:
            diff.changed.append(DiffItem(by_id[eid], changed, note="details changed"))

    failed_b, included_b = set(run_b.tools_failed or []), set(run_b.tools_included or [])
    for eid in seen_a.keys() - seen_b.keys():
        tools = sorted(seen_a[eid])
        failed = [t for t in tools if t in failed_b]
        missing = [t for t in tools if t not in included_b]
        if failed:
            note, real = f"not a real disappearance: {', '.join(failed)} failed in run #{run_b.run_number}", False
        elif missing:
            note, real = f"not a real disappearance: {', '.join(missing)} did not run in #{run_b.run_number}", False
        else:
            note, real = f"no longer reported by {', '.join(tools)}", True
        diff.gone.append(DiffItem(by_id[eid], tools, note, real))

    key = lambda item: (not item.entity.is_seed, -item.entity.confidence)  # noqa: E731
    diff.new.sort(key=key)
    diff.changed.sort(key=key)
    diff.gone.sort(key=lambda item: (not item.real, -item.entity.confidence))
    return diff
