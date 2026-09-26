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
from app.models import Entity, EntityObservation, Investigation, Relation, ScanRun, Target, ToolConfig
from app.services.tools import record_failure, record_success, tool_configs
from app.throttle import tool_slot

log = logging.getLogger(__name__)

TRIGGER_PRIORITY = {"manual": 0, "pivot_chain": 5, "watch_mode": 10, "health_check": 20}


@dataclass
class Job:
    target_id: uuid.UUID
    tool: str


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
            jobs.append(Job(target.id, adapter.name))
    return jobs


async def create_scan_run(
    session: AsyncSession,
    case: Investigation,
    *,
    triggered_by: str = "manual",
    only_tools: list[str] | None = None,
) -> ScanRun:
    # Serialise run numbering per case.
    await session.execute(select(Investigation.id).where(Investigation.id == case.id).with_for_update())
    last = await session.scalar(select(func.max(ScanRun.run_number)).where(ScanRun.case_id == case.id))
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
    target: Target,
    tool: str,
    candidates: list[EntityCandidate],
) -> int:
    """Upsert candidates as entities, record observations and relations."""
    now = datetime.now(UTC)
    seed = await session.scalar(
        select(Entity).where(
            Entity.case_id == run.case_id,
            Entity.is_seed.is_(True),
            Entity.type == target.type,
            Entity.value_digest == target.value_digest,
        )
    )
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
        await session.commit()


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
            target = await session.get(Target, job.target_id)
            assert target is not None
            target_value, tags = target.value, list(target.context_tags or [])
        timeout = adapter.timeout_seconds or get_settings().tool_timeout_seconds
        async with tool_slot(
            adapter.name,
            cfg.max_concurrent,
            lease_seconds=timeout + 120,
            delay_seconds=cfg.delay_between_requests_ms / 1000,
        ):
            raws = await adapter.run(target_value, tags)
        candidates = [c for raw in raws for c in adapter.parse(raw)]
        async with sessionmaker()() as session:
            await _lock_case(session, case_id)
            run = await session.get(ScanRun, run_id)
            target = await session.get(Target, job.target_id)
            assert run is not None and target is not None
            await persist_candidates(session, run=run, target=target, tool=adapter.name, candidates=candidates)
            await session.commit()
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
        jobs = await plan_jobs(session, case, list(run.tools_included))
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
