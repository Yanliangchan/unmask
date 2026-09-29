"""Scan orchestration: dispatch targets to adapters and persist what they find.

A failing adapter never fails the whole scan. Each (target, tool) pair is an
isolated job: its failure is written to ``scan_runs.tools_failed`` /
``failure_details`` and counted against the tool's circuit breaker, and the
remaining jobs carry on.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select, text
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto
from app.adapters.base import AdapterError, EntityCandidate, InvalidTarget, ToolAdapter
from app.adapters.registry import adapters_for, get_adapter
from app.config import get_settings
from app.db import sessionmaker
from app.models import Entity, EntityObservation, Investigation, PivotLog, Relation, ScanRun, Target, ToolConfig
from app.services.accuracy import site_host
from app.services.tools import record_failure, record_success, tool_configs
from app.throttle import tool_slot
from app.verify import VerificationStats, linked_accounts, verify_candidates

log = logging.getLogger(__name__)

CANCELLED = "cancelled"
ACTIVE = ("queued", "running")

TRIGGER_PRIORITY = {"manual": 0, "pivot_chain": 5, "watch_mode": 10, "health_check": 20}


@dataclass
class Job:
    """One tool run: against an analyst target, or against a pivot's inputs."""

    tool: str
    target_id: uuid.UUID | None = None
    pivot_id: uuid.UUID | None = None


async def plan_jobs(session: AsyncSession, case: Investigation, only_tools: list[str] | None = None) -> list[Job]:
    cfgs = await tool_configs(session)
    targets = (await session.scalars(select(Target).where(Target.case_id == case.id))).all()
    jobs = []
    for target in targets:
        for adapter in adapters_for(target.type):
            cfg = cfgs.get(adapter.name)
            if cfg is None or not cfg.enabled or adapter.configured() is not None:
                continue
            if adapter.name in (case.disabled_tools or []):
                continue
            if only_tools is not None and adapter.name not in only_tools:
                continue
            jobs.append(Job(adapter.name, target_id=target.id))
    return jobs


async def plan_run_jobs(session: AsyncSession, case: Investigation, run: ScanRun) -> list[Job]:
    if run.triggered_by == "pivot_chain":
        rows = (await session.scalars(select(PivotLog).where(PivotLog.scan_run_id == run.id))).all()
        return [Job(row.triggered_tool, pivot_id=row.id) for row in rows]
    return await plan_jobs(session, case, list(run.tools_included))


async def create_scan_run(
    session: AsyncSession,
    case: Investigation,
    *,
    triggered_by: str = "manual",
    only_tools: list[str] | None = None,
    jobs: list[Job] | None = None,
) -> ScanRun:
    # Serialise run numbering per case.
    await session.execute(select(Investigation.id).where(Investigation.id == case.id).with_for_update())
    last = await session.scalar(select(func.max(ScanRun.run_number)).where(ScanRun.case_id == case.id))
    if jobs is None:
        jobs = await plan_jobs(session, case, only_tools)
    run = ScanRun(
        case_id=case.id,
        run_number=(last or 0) + 1,
        status="queued",
        triggered_by=triggered_by,
        priority=TRIGGER_PRIORITY.get(triggered_by, 10),
        tools_included=sorted({j.tool for j in jobs}),
        tools_completed=[],
        tools_failed=[],
        failure_details={},
        jobs_total=len(jobs),
        jobs_done=0,
    )
    session.add(run)
    await session.flush()
    return run


def _attributes_digest(attrs: dict) -> str:
    return hashlib.sha256(json.dumps(attrs, sort_keys=True, default=str).encode()).hexdigest()


async def _lock_case(session: AsyncSession, case_id: uuid.UUID) -> None:
    await session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": str(case_id)})


async def persist_candidates(
    session: AsyncSession,
    *,
    run: ScanRun,
    parent: Entity | None,
    tool: str,
    candidates: list[EntityCandidate],
) -> int:
    """Upsert candidates as entities, record observations and link them to ``parent``.

    ``parent`` is the target's seed entity for a direct scan, or the triggering
    entity for a pivot.
    """
    now = datetime.now(UTC)
    seed = parent
    created = 0
    for cand in candidates:
        value_digest = crypto.digest(cand.type, cand.value)
        # Merged-away entities are matched too: a re-sighting is recorded on the
        # member (keeping diffs exact) instead of resurrecting a duplicate.
        entity = await session.scalar(
            select(Entity)
            .where(
                Entity.case_id == run.case_id,
                Entity.type == cand.type,
                Entity.value_digest == value_digest,
            )
            .order_by(Entity.merged_into_id.is_not(None), Entity.first_seen)
            .limit(1)
        )
        if entity is None:
            entity = Entity(
                case_id=run.case_id,
                scan_run_id=run.id,
                type=cand.type,
                value=cand.value,
                value_digest=value_digest,
                attributes=cand.attributes,
                source_tool=tool,
                confidence=max(0.0, min(1.0, cand.confidence)),
                # The adapter's estimate is kept as the prior the correlation
                # engine rescores from, so rescoring is idempotent.
                field_confidence={**cand.field_confidence, "prior": max(0.0, min(1.0, cand.confidence))},
                source_reliability=cand.source_reliability,
                verification=cand.attributes.get("verification"),
                site_host=site_host(cand.value) if cand.type == "account" else None,
                first_seen=now,
                last_verified=now,
            )
            session.add(entity)
            await session.flush()
            created += 1
        else:
            entity.last_verified = now
            entity.attributes = {**(entity.attributes or {}), **cand.attributes}
            # Keep the most reliable source class that has reported this value.
            entity.source_reliability = min(entity.source_reliability, cand.source_reliability)
            # A page that verified once stays verified; a later blocked fetch doesn't undo it.
            if cand.attributes.get("verification") == "verified" or entity.verification is None:
                entity.verification = cand.attributes.get("verification") or entity.verification
            if entity.verification == "verified":
                entity.attributes = {**entity.attributes, "verification": "verified"}
            prior = max(float((entity.field_confidence or {}).get("prior", 0.0)), cand.confidence)
            entity.field_confidence = {**cand.field_confidence, **(entity.field_confidence or {}), "prior": prior}
        await session.execute(
            insert(EntityObservation)
            .values(
                entity_id=entity.id,
                scan_run_id=run.id,
                source_tool=tool,
                confidence=cand.confidence,
                attributes_digest=_attributes_digest(cand.attributes),
                observed_at=now,
            )
            .on_conflict_do_nothing(constraint="uq_entity_observations")
        )
        if seed is not None and cand.relation_type and seed.id != entity.id:
            exists = await session.scalar(
                select(Relation.id).where(
                    Relation.entity_a_id == seed.id,
                    Relation.entity_b_id == entity.id,
                    Relation.relation_type == cand.relation_type,
                    Relation.source_tool == tool,
                )
            )
            if exists is None:
                session.add(
                    Relation(
                        case_id=run.case_id,
                        entity_a_id=seed.id,
                        entity_b_id=entity.id,
                        relation_type=cand.relation_type,
                        source_tool=tool,
                        match_explanation=cand.relation_explanation,
                        confidence=cand.confidence,
                    )
                )
    if seed is not None:
        seed.last_verified = now
    return created


async def _record_job_outcome(
    run_id: uuid.UUID, case_id: uuid.UUID, tool: str, error: str | None, count_against_tool: bool
) -> None:
    tripped = 0
    async with sessionmaker()() as session:
        await _lock_case(session, case_id)
        run = await session.get(ScanRun, run_id, with_for_update=True)
        cfg = await session.get(ToolConfig, tool, with_for_update=True)
        assert run is not None
        run.jobs_done += 1
        if error is None:
            if tool not in run.tools_completed:
                run.tools_completed = [*run.tools_completed, tool]
            if cfg is not None:
                record_success(cfg)
        else:
            if tool not in run.tools_failed:
                run.tools_failed = [*run.tools_failed, tool]
            details = dict(run.failure_details or {})
            details[tool] = f"{details[tool]} | {error}" if tool in details else error
            run.failure_details = details
            if cfg is not None and count_against_tool and record_failure(cfg, error):
                log.warning("circuit breaker opened for %s: %s", tool, error)
                tripped = cfg.consecutive_failures
        await session.commit()
    if tripped:
        from app.alerts import send_alert

        await send_alert(f"circuit breaker opened: {tool} disabled after {tripped} consecutive failures")


def _record_verification(run: ScanRun, tool: str, stats: VerificationStats) -> None:
    """Add this job's page-check counts to the run's notes (summed per tool)."""
    notes = dict(run.failure_details or {})
    by_tool = dict(notes.get("_verification") or {})
    prev = by_tool.get(tool) or {"counts": {}, "reasons": {}}
    counts = {k: prev["counts"].get(k, 0) + v for k, v in stats.counts.items()}
    counts = {**prev["counts"], **counts}
    reasons = dict(prev["reasons"])
    for k, v in stats.reasons.items():
        reasons[k] = reasons.get(k, 0) + v
    by_tool[tool] = {"counts": counts, "reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])[:5])}
    notes["_verification"] = by_tool
    run.failure_details = notes


async def seed_entity(session: AsyncSession, target: Target) -> Entity | None:
    return await session.scalar(
        select(Entity).where(
            Entity.case_id == target.case_id,
            Entity.is_seed.is_(True),
            Entity.type == target.type,
            Entity.value_digest == target.value_digest,
        )
    )


@dataclass
class _JobInputs:
    values: list  # list[PivotInput]-like: .value, .guessed
    tags: list[str]
    parent_id: uuid.UUID | None


async def _resolve_inputs(session: AsyncSession, case_id: uuid.UUID, job: Job) -> _JobInputs:
    from app.pivots.engine import pivot_inputs
    from app.pivots.rules import PivotInput

    if job.target_id is not None:
        target = await session.get(Target, job.target_id)
        assert target is not None
        seed = await seed_entity(session, target)
        return _JobInputs(
            [PivotInput(target.type, target.value)], list(target.context_tags or []), seed.id if seed else None
        )
    row = await session.get(PivotLog, job.pivot_id)
    assert row is not None
    inputs, parent_id = await pivot_inputs(session, row)
    tags = sorted({t for tg in (await session.scalars(select(Target).where(Target.case_id == case_id))).all()
                   for t in (tg.context_tags or [])})  # fmt: skip
    return _JobInputs(inputs, tags, parent_id)


def _guess_confirmed(inp, candidates: list[EntityCandidate], tool: str) -> EntityCandidate:
    """A guessed email that turned out to be registered somewhere becomes an entity."""
    return EntityCandidate(
        type="email",
        value=inp.value,
        attributes={"origin": "guessed from username", "confirmed_by": tool, "registrations": len(candidates)},
        source_reliability="C",
        confidence=0.45,
        field_confidence={"registered": 0.8, "same_person": 0.45},
        relation_type="guessed_email",
        relation_explanation=f"guessed address; {tool} found it registered on {len(candidates)} site(s)",
    )


async def _run_job(
    run_id: uuid.UUID,
    case_id: uuid.UUID,
    job: Job,
    adapter: ToolAdapter,
    cfg: ToolConfig,
) -> None:
    error: str | None = None
    count_against_tool = True
    try:
        async with sessionmaker()() as session:
            inputs = await _resolve_inputs(session, case_id, job)
        timeout = adapter.timeout_seconds or get_settings().tool_timeout_seconds
        candidates: list[EntityCandidate] = []
        errors: list[str] = []
        verification = VerificationStats()
        for inp in inputs.values:
            try:
                async with tool_slot(
                    adapter.name,
                    cfg.max_concurrent,
                    lease_seconds=timeout + 120,
                    delay_seconds=cfg.delay_between_requests_ms / 1000,
                ):
                    raws = await adapter.run(inp.value, inputs.tags)
            except AdapterError as exc:
                if len(inputs.values) == 1:
                    raise
                errors.append(str(exc) or exc.__class__.__name__)
                continue
            found = [c for raw in raws for c in adapter.parse(raw)]
            if adapter.verify_accounts:
                found, stats = await verify_candidates(found)
                verification.merge(stats)
                # One hop only: accounts the verified profiles link to, checked the same way.
                linked, linked_stats = await verify_candidates(linked_accounts(found))
                verification.merge(linked_stats)
                found.extend(linked)
            if inp.guessed and found:
                found.append(_guess_confirmed(inp, found, adapter.name))
            candidates.extend(found)
        async with sessionmaker()() as session:
            await _lock_case(session, case_id)
            run = await session.get(ScanRun, run_id)
            parent = await session.get(Entity, inputs.parent_id) if inputs.parent_id else None
            assert run is not None
            if run.status == CANCELLED:
                return
            await persist_candidates(session, run=run, parent=parent, tool=adapter.name, candidates=candidates)
            if verification.counts:
                _record_verification(run, adapter.name, verification)
            await session.commit()
        if candidates:
            await _quick_rescore(case_id)
        if errors:
            # Some inputs failed: the pivot did not fully run, so say so.
            raise AdapterError(f"{len(errors)}/{len(inputs.values)} input(s) failed: {errors[0]}")
    except InvalidTarget as exc:
        # Bad input, not a broken tool: log it but don't trip the breaker.
        error, count_against_tool = f"invalid target: {exc}", False
    except AdapterError as exc:
        error = str(exc) or exc.__class__.__name__
    except Exception as exc:  # noqa: BLE001 — a crashing adapter must not kill the scan
        log.exception("adapter %s crashed", adapter.name)
        error = f"unexpected error: {exc.__class__.__name__}: {exc}"
    await _record_job_outcome(run_id, case_id, adapter.name, error, count_against_tool)


async def execute_scan_run(run_id: uuid.UUID) -> None:
    async with sessionmaker()() as session:
        run = await session.get(ScanRun, run_id)
        if run is None or run.status not in ("queued",):
            return
        case = await session.get(Investigation, run.case_id)
        assert case is not None
        run.status = "running"
        run.started_at = datetime.now(UTC)
        jobs = await plan_run_jobs(session, case, run)
        cfgs = await tool_configs(session)
        await session.commit()
        case_id = case.id

    tasks = []
    for job in jobs:
        adapter = get_adapter(job.tool)
        if adapter is None:
            continue
        tasks.append(_run_job(run_id, case_id, job, adapter, cfgs[job.tool]))
    await asyncio.gather(*tasks)

    async with sessionmaker()() as session:
        run = await session.get(ScanRun, run_id)
        assert run is not None
        if run.status == CANCELLED:
            return
        # Jobs planned at queue time may have been dropped (tool disabled since).
        if run.jobs_done < run.jobs_total:
            details = dict(run.failure_details or {})
            details["_skipped"] = (
                f"{run.jobs_total - run.jobs_done} job(s) skipped: "
                "tool disabled or unconfigured after the scan was queued"
            )
            run.failure_details = details
            run.jobs_done = run.jobs_total
        if run.tools_failed and not run.tools_completed:
            run.status = "failed"
        elif run.tools_failed or "_skipped" in (run.failure_details or {}):
            run.status = "partial"
        else:
            run.status = "completed"
        if run.jobs_total == 0:
            run.failure_details = {
                **(run.failure_details or {}),
                "_none": "No enabled tool accepts these target types yet",
            }
        run.completed_at = datetime.now(UTC)
        await session.commit()

    await _correlate_after_run(run_id, case_id)
    await _notify_after_run(run_id)
    await _pivot_after_run(run_id, case_id)


async def _notify_after_run(run_id: uuid.UUID) -> None:
    """Notifications are a courtesy: a failure here never fails the scan."""
    from app.services.notifications import notify_scan_finished

    try:
        async with sessionmaker()() as session:
            run = await session.get(ScanRun, run_id)
            if run is not None:
                await notify_scan_finished(session, run)
                await session.commit()
    except Exception:
        log.exception("scan notifications failed for run %s", run_id)


async def _pivot_after_run(run_id: uuid.UUID, case_id: uuid.UUID) -> None:
    """Start the pivot run this run's findings call for. Errors are recorded, never fatal."""
    from app.jobs import enqueue_scan
    from app.pivots.engine import evaluate_pivots

    try:
        async with sessionmaker()() as session:
            outcome = await evaluate_pivots(session, case_id, run_id)
            await session.commit()
        if outcome.run_id is not None:
            enqueue_scan(outcome.run_id, "pivot_chain")
        note, key = outcome.summary(), "_pivots"
    except Exception as exc:
        log.exception("pivot evaluation failed for case %s", case_id)
        note, key = f"{exc.__class__.__name__}: {exc}", "_pivots_error"
    if note:
        async with sessionmaker()() as session:
            run = await session.get(ScanRun, run_id)
            if run is not None:
                run.failure_details = {**(run.failure_details or {}), key: note}
                await session.commit()


async def _quick_rescore(case_id: uuid.UUID) -> None:
    """Merge and rescore right after a tool reports, so its results show up scored mid-scan.

    Pass 2 (embeddings) waits for the end of the run. Failures here are only
    logged: the full correlation after the run is the one that is recorded.
    """
    from app.correlation.engine import correlate_and_commit

    try:
        async with sessionmaker()() as session:
            await correlate_and_commit(session, case_id, semantic=False)
    except Exception:
        log.exception("quick rescore failed for case %s", case_id)


async def _correlate_after_run(run_id: uuid.UUID, case_id: uuid.UUID) -> None:
    """Correlate once results are in. A correlation error is recorded, never fatal to the scan."""
    from app.correlation.engine import correlate_and_commit

    try:
        async with sessionmaker()() as session:
            summary = (await correlate_and_commit(session, case_id)).summary()
    except Exception as exc:
        log.exception("correlation failed for case %s", case_id)
        summary = None
        error = f"{exc.__class__.__name__}: {exc}"
    async with sessionmaker()() as session:
        run = await session.get(ScanRun, run_id)
        if run is not None:
            key, value = ("_correlation", summary) if summary else ("_correlation_error", error)
            run.failure_details = {**(run.failure_details or {}), key: value}
            await session.commit()


async def cancel_scan_run(session: AsyncSession, run: ScanRun, *, by: str) -> bool:
    """Stop a queued or running scan. Results already stored are kept. Caller commits."""
    if run.status not in ACTIVE:
        return False
    run.status = CANCELLED
    run.completed_at = datetime.now(UTC)
    run.failure_details = {
        **(run.failure_details or {}),
        "_cancelled": f"stopped by {by} after {run.jobs_done} of {run.jobs_total} tool runs",
    }
    return True


async def fail_interrupted_runs(session: AsyncSession, older_than: timedelta | None = None) -> int:
    """Mark runs a dead process left queued/running as failed, never leave them hanging.

    With the inline backend every unfinished run died with the process
    (``older_than=None``). With RQ, runs are only reaped once they have been
    unfinished for longer than the job timeout.
    """
    stmt = select(ScanRun).where(ScanRun.status.in_(("queued", "running")))
    if older_than is not None:
        stmt = stmt.where(ScanRun.created_at < datetime.now(UTC) - older_than)
    runs = (await session.scalars(stmt)).all()
    for run in runs:
        run.status = "failed"
        run.completed_at = datetime.now(UTC)
        run.failure_details = {
            **(run.failure_details or {}),
            "_interrupted": "scan interrupted (worker restarted or timed out)",
        }
    await session.commit()
    return len(runs)


async def mark_run_crashed(run_id: uuid.UUID, error: str) -> None:
    async with sessionmaker()() as session:
        run = await session.get(ScanRun, run_id)
        if run is None or run.status not in ("queued", "running"):
            return
        run.status = "failed"
        run.completed_at = datetime.now(UTC)
        run.failure_details = {**(run.failure_details or {}), "_crashed": error[:1000]}
        await session.commit()
