"""Pivot evaluation: turn new findings into follow-up tool runs, visibly.

After each scan run is correlated, every rule is checked against the case's
entities. A qualifying entity gets one ``pivot_log`` row per tool; together
they form a new ``pivot_chain`` scan run. Pivots that can't run — depth limit,
per-evaluation budget, tool unavailable — are logged as skipped with the
reason, so the Pivot Log accounts for every decision.

A tool never runs twice on the same input within a case, whether that input
was an analyst target or produced by an earlier pivot.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.adapters.registry import adapters_for, get_adapter
from app.config import get_settings
from app.correlation import normalize as norm
from app.jobs import scan_job_id
from app.models import Entity, Investigation, PivotLog, ScanRun, Target
from app.pivots import rules as pivot_rules
from app.pivots.rules import PivotInput, PivotRule, rule_from_text, rule_text
from app.services.tools import tool_configs

InputKey = tuple[str, str, str]  # (tool, input type, canonical value)


def _key(tool: str, inp: PivotInput) -> InputKey:
    return (tool, inp.type, norm.canonical(inp.type, inp.value))


def auto_pivot_enabled(case: Investigation) -> bool:
    return bool((case.watch_config or {}).get("auto_pivot", True))


async def executed_inputs(session: AsyncSession, case_id: uuid.UUID) -> set[InputKey]:
    """Every (tool, input) the case has already run or queued."""
    done: set[InputKey] = set()
    targets = (await session.scalars(select(Target).where(Target.case_id == case_id))).all()
    runs = (
        await session.scalars(select(ScanRun).where(ScanRun.case_id == case_id, ScanRun.triggered_by != "pivot_chain"))
    ).all()
    for run in runs:
        for target in targets:
            for adapter in adapters_for(target.type):
                if adapter.name in run.tools_included:
                    done.add(_key(adapter.name, PivotInput(target.type, target.value)))
    rows = (
        await session.scalars(select(PivotLog).where(PivotLog.case_id == case_id, PivotLog.scan_run_id.is_not(None)))
    ).all()
    entity_ids = {r.triggering_entity_id for r in rows if r.triggering_entity_id}
    values = {e.id: e.value for e in (await session.scalars(select(Entity).where(Entity.id.in_(entity_ids)))).all()}
    for row in rows:
        rule = rule_from_text(row.rule_matched)
        if rule and row.triggering_entity_id in values:
            done.update(_key(rule.tool, inp) for inp in rule.expand(values[row.triggering_entity_id]))
    return done


async def pivot_inputs(session: AsyncSession, row: PivotLog) -> tuple[list[PivotInput], uuid.UUID | None]:
    """The inputs a pivot row runs on, recomputed from its rule and triggering entity."""
    rule = rule_from_text(row.rule_matched)
    entity = await session.get(Entity, row.triggering_entity_id) if row.triggering_entity_id else None
    if rule is None or entity is None:
        return [], None
    return rule.expand(entity.value), entity.id


async def run_depth(session: AsyncSession, run: ScanRun | None) -> int:
    """How many pivot runs deep ``run`` is (0 for an analyst- or watch-started run)."""
    depth = 0
    for _ in range(20):  # bounded walk; chains are capped far below this
        if run is None or run.triggered_by != "pivot_chain":
            return depth
        row = await session.scalar(select(PivotLog).where(PivotLog.scan_run_id == run.id).limit(1))
        entity = await session.get(Entity, row.triggering_entity_id) if row and row.triggering_entity_id else None
        depth += 1
        run = await session.get(ScanRun, entity.scan_run_id) if entity and entity.scan_run_id else None
    return depth


@dataclass
class PivotOutcome:
    run_id: uuid.UUID | None = None
    run_number: int | None = None
    started: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    disabled: bool = False

    def summary(self) -> str:
        if self.disabled:
            return "automatic pivoting is off for this case"
        parts = []
        if self.started:
            parts.append(f"{len(self.started)} pivot(s) started as run #{self.run_number}")
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped (see Pivot Log)")
        return "; ".join(parts)


def _unavailable(rule: PivotRule, case: Investigation, cfgs) -> str | None:
    adapter = get_adapter(rule.tool)
    if adapter is None:
        return f"{rule.tool} is not installed"
    cfg = cfgs.get(rule.tool)
    if cfg is None or not cfg.enabled:
        return f"{adapter.label} is disabled" + (" by the circuit breaker" if cfg and cfg.circuit_open else "")
    if adapter.configured() is not None:
        return f"{adapter.label} not configured"
    if rule.tool in (case.disabled_tools or []):
        return f"{adapter.label} is excluded from this case"
    return None


async def evaluate_pivots(session: AsyncSession, case_id: uuid.UUID, source_run_id: uuid.UUID) -> PivotOutcome:
    """Log and plan pivots from the case's current findings. Caller commits and enqueues."""
    from app.correlation.engine import lock_case
    from app.services.scans import Job, create_scan_run

    await lock_case(session, case_id)
    outcome = PivotOutcome()
    case = await session.get(Investigation, case_id)
    source = await session.get(ScanRun, source_run_id)
    if case is None or source is None:
        return outcome
    if not auto_pivot_enabled(case):
        outcome.disabled = True
        return outcome

    settings = get_settings()
    depth = await run_depth(session, source) + 1
    cfgs = await tool_configs(session)
    done = await executed_inputs(session, case_id)
    already = {
        (r.triggering_entity_id, r.triggered_tool)
        for r in (await session.scalars(select(PivotLog).where(PivotLog.case_id == case_id))).all()
    }
    entities = (
        await session.scalars(
            select(Entity)
            .where(Entity.case_id == case_id, Entity.merged_into_id.is_(None))
            .order_by(Entity.confidence.desc(), Entity.first_seen)
        )
    ).all()

    pending: list[PivotLog] = []
    for entity in entities:
        for rule in pivot_rules.RULES:
            if entity.type != rule.entity_type or entity.confidence <= rule.min_confidence:
                continue
            if (entity.id, rule.tool) in already:
                continue
            fresh = [inp for inp in rule.expand(entity.value) if _key(rule.tool, inp) not in done]
            if not fresh:
                continue  # everything this rule would run has already run
            reason = _unavailable(rule, case, cfgs)
            if reason is None and depth > settings.pivot_max_depth:
                reason = f"pivot depth limit ({settings.pivot_max_depth}) reached"
            if reason is None and len(pending) >= settings.pivot_budget:
                reason = f"pivot budget ({settings.pivot_budget} per evaluation) reached"
            row = PivotLog(
                case_id=case_id,
                triggering_entity_id=entity.id,
                triggered_tool=rule.tool,
                rule_matched=rule_text(rule, entity.confidence, f"skipped: {reason}" if reason else None),
                confidence_at_trigger=entity.confidence,
            )
            session.add(row)
            already.add((entity.id, rule.tool))
            if reason:
                outcome.skipped.append(rule.tool)
            else:
                pending.append(row)
                done.update(_key(rule.tool, inp) for inp in fresh)
                outcome.started.append(rule.tool)
    await session.flush()

    if pending:
        run = await create_scan_run(
            session,
            case,
            triggered_by="pivot_chain",
            jobs=[Job(row.triggered_tool, pivot_id=row.id) for row in pending],
        )
        for row in pending:
            row.scan_run_id = run.id
            row.job_id = scan_job_id(run.id)
        outcome.run_id, outcome.run_number = run.id, run.run_number
        await session.flush()
    return outcome
