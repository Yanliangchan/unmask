"""Case report: a narrative summary for a reader who wasn't at the keyboard.

The report presents correlated evidence; the conclusion is the analyst's own,
written assessment, which is required before anything can be exported.
Contradiction flags are heuristics and say so.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.correlation import normalize as norm
from app.correlation.engine import POSSIBLE_SAME
from app.models import SOURCE_RELIABILITY, Entity, EntityObservation, Investigation, PivotLog, Relation, ScanRun, User
from app.services.timeline import default_pair, diff_runs

MIN_ASSESSMENT_CHARS = 40
TIERS = [("High confidence", 0.75, 1.01), ("Medium confidence", 0.45, 0.75), ("Low confidence", 0.0, 0.45)]
PROFILE_FIELDS = {"location": "location", "fullname": "name", "name": "name", "country": "country", "city": "city"}


class AssessmentRequired(Exception):
    pass


@dataclass
class ReportEntity:
    entity: Entity
    sources: list[str]
    merged: int


@dataclass
class Contradiction:
    title: str
    detail: str


@dataclass
class Report:
    case: Investigation
    generated_at: datetime
    generated_by: str
    tiers: list[tuple[str, list[ReportEntity]]]
    runs: list[ScanRun]
    pending_suggestions: int
    contradictions: list[Contradiction]
    coverage_gaps: list[str]
    pivots_run: int
    pivots_skipped: int
    diff_summary: str | None
    entity_count: int
    reliability_scale: dict = field(default_factory=lambda: SOURCE_RELIABILITY)


def assessment_ready(case: Investigation) -> bool:
    return len((case.analyst_assessment or "").strip()) >= MIN_ASSESSMENT_CHARS


def _profile_values(entities: list[Entity]) -> dict[str, list[tuple[str, str]]]:
    """field -> [(value, where)] from account profiles."""
    found: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for e in entities:
        profile = (e.attributes or {}).get("profile") or {}
        site = (e.attributes or {}).get("site") or e.value
        for key, label in PROFILE_FIELDS.items():
            if profile.get(key):
                found[label].append((str(profile[key]).strip(), str(site)))
    return found


def find_contradictions(active: list[Entity], members: dict[uuid.UUID, list[Entity]]) -> list[Contradiction]:
    out: list[Contradiction] = []
    # 1. Sources disagree about the same profile field across the subject's accounts.
    for label, values in _profile_values([e for e in active if e.type == "account"]).items():
        distinct: dict[str, list[str]] = defaultdict(list)
        for value, site in values:
            distinct[norm.canonical_name(value) if label == "name" else norm.fold(value)].append(f"'{value}' ({site})")
        if len(distinct) < 2:
            continue
        if label == "name":
            names = [v[0] for v in values]
            if all(norm.initials_compatible(a, b) for a in names for b in names):
                continue  # "Yan Chan" vs "Yan Liang Chan" is not a contradiction
        out.append(Contradiction(f"Accounts disagree on {label}", "; ".join(v[0] for v in distinct.values())))
    # 2. Values merged as one identifier whose sources report different details.
    for winner in active:
        group = [winner, *members.get(winner.id, [])]
        if len(group) < 2:
            continue
        for key, label in PROFILE_FIELDS.items():
            vals = {
                norm.fold(str(((m.attributes or {}).get("profile") or {}).get(key))): m.source_tool
                for m in group
                if ((m.attributes or {}).get("profile") or {}).get(key)
            }
            if len(vals) > 1:
                detail = "; ".join(f"'{v}' ({tool})" for v, tool in vals.items())
                out.append(Contradiction(f"Merged {winner.type} reports different {label}", detail))
    return out


async def build_report(session: AsyncSession, case: Investigation, user: User) -> Report:
    if not assessment_ready(case):
        raise AssessmentRequired
    entities = list((await session.scalars(select(Entity).where(Entity.case_id == case.id))).all())
    active = [e for e in entities if e.merged_into_id is None]
    members: dict[uuid.UUID, list[Entity]] = defaultdict(list)
    for e in entities:
        if e.merged_into_id:
            members[e.merged_into_id].append(e)
    owner = {e.id: (e.merged_into_id or e.id) for e in entities}
    sources: dict[uuid.UUID, set[str]] = defaultdict(set)
    for e in entities:
        sources[owner[e.id]].add(e.source_tool)
    for eid, tool in (
        await session.execute(
            select(EntityObservation.entity_id, EntityObservation.source_tool).where(
                EntityObservation.entity_id.in_(list(owner))
            )
        )
    ).all():
        sources[owner[eid]].add(tool)

    tiers = []
    for label, lo, hi in TIERS:
        rows = [
            ReportEntity(e, sorted(sources[e.id]), len(members.get(e.id, [])))
            for e in sorted(active, key=lambda e: (not e.is_seed, not e.confirmed_flag, -e.confidence, e.type))
            if lo <= e.confidence < hi
        ]
        tiers.append((label, rows))

    runs = list(
        (await session.scalars(select(ScanRun).where(ScanRun.case_id == case.id).order_by(ScanRun.run_number))).all()
    )
    rels = (await session.scalars(select(Relation).where(Relation.case_id == case.id))).all()
    pending = sum(1 for r in rels if r.relation_type == POSSIBLE_SAME)
    pivots = (await session.scalars(select(PivotLog).where(PivotLog.case_id == case.id))).all()

    gaps = []
    latest_by_tool: dict[str, ScanRun] = {}
    for run in runs:
        for tool in run.tools_included:
            latest_by_tool[tool] = run
    for tool, run in sorted(latest_by_tool.items()):
        if tool in (run.tools_failed or []):
            gaps.append(f"{tool} failed in its latest run (#{run.run_number}): its findings may be incomplete")

    diff_summary = None
    a, b = default_pair(runs)
    if a and b:
        d = await diff_runs(session, case.id, a, b)
        real_gone = sum(1 for i in d.gone if i.real)
        diff_summary = (
            f"Run #{a.run_number} → #{b.run_number}: {len(d.new)} new, {len(d.changed)} changed, "
            f"{real_gone} no longer found"
            + (f" ({len(d.gone) - real_gone} more explained by tool failures)" if len(d.gone) > real_gone else "")
        )

    return Report(
        case=case,
        generated_at=datetime.now(UTC),
        generated_by=user.email,
        tiers=tiers,
        runs=runs,
        pending_suggestions=pending,
        contradictions=find_contradictions(active, members),
        coverage_gaps=gaps,
        pivots_run=sum(1 for p in pivots if p.scan_run_id),
        pivots_skipped=sum(1 for p in pivots if not p.scan_run_id),
        diff_summary=diff_summary,
        entity_count=len(active),
    )


# --- Markdown -------------------------------------------------------------------------


def _code(value: str) -> str:
    value = value.replace("\n", " ").replace("|", "\\|")
    return f"`` {value} ``" if "`" in value else f"`{value}`"


def _text(value: str) -> str:
    """Neutralise Markdown in free text taken from tools or analysts."""
    for ch in "\\`*_[]<>|#":
        value = value.replace(ch, "\\" + ch)
    return value


def _dt(value: datetime | None) -> str:
    return value.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC") if value else "—"


def render_markdown(r: Report) -> str:
    c = r.case
    lines = [
        f"# Case report: {_text(c.name)}",
        "",
        f"Generated {_dt(r.generated_at)} by {_text(r.generated_by)} · case `{c.id}`",
        "",
        "> This report presents correlated open-source findings. Confidence scores estimate whether a",
        "> finding relates to the subject; they are not conclusions. The conclusion is the analyst",
        "> assessment below, written by a person.",
        "",
        "## Analyst assessment",
        "",
        *[_text(line) for line in (c.analyst_assessment or "").strip().splitlines()],
        "",
        f"*Last updated {_dt(c.analyst_assessment_updated_at)}.*",
        "",
        "## Authorization",
        "",
        _text(c.authorization_note.strip()),
        "",
        f"Lawful basis confirmed {_dt(c.lawful_basis_confirmed_at)}.",
        "",
        "## Targets",
        "",
        "| Type | Value | Context tags |",
        "|---|---|---|",
        *[f"| {t.type} | {_code(t.value)} | {_text(', '.join(t.context_tags or [])) or '—'} |" for t in c.targets],
        "",
        "## Findings",
        "",
        f"{r.entity_count} entities after de-duplication; {r.pending_suggestions} suggested match(es) not yet "
        "reviewed by an analyst.",
        "",
    ]
    for label, rows in r.tiers:
        lines += [f"### {label} ({len(rows)})", ""]
        if not rows:
            lines += ["None.", ""]
            continue
        lines += ["| Value | Type | Confidence | Reliability | Sources | Notes |", "|---|---|---|---|---|---|"]
        for row in rows:
            e = row.entity
            notes = [n for n in ("target" if e.is_seed else "", "confirmed by analyst" if e.confirmed_flag else "",
                                 f"{row.merged} duplicate(s) merged" if row.merged else "") if n]  # fmt: skip
            lines.append(
                f"| {_code(e.value)} | {e.type} | {e.confidence:.2f} | {e.source_reliability} "
                f"| {', '.join(row.sources)} | {'; '.join(notes) or '—'} |"
            )
        lines.append("")

    lines += ["## Contradictions between sources", ""]
    if r.contradictions:
        lines += [f"- **{_text(x.title)}:** {_text(x.detail)}" for x in r.contradictions]
        lines += ["", "*Flagged automatically by comparing profile fields; review before relying on either value.*"]
    else:
        lines.append("None flagged.")
    lines += ["", "## Scan timeline", ""]
    lines += ["| Run | Trigger | Status | Started | Tools | Failed |", "|---|---|---|---|---|---|"]
    for run in r.runs:
        lines.append(
            f"| #{run.run_number} | {run.triggered_by.replace('_', ' ')} | {run.status} | {_dt(run.started_at)} "
            f"| {', '.join(run.tools_included) or '—'} | {', '.join(run.tools_failed) or '—'} |"
        )
    lines.append("")
    if r.diff_summary:
        lines += [f"Latest comparison: {r.diff_summary}.", ""]
    lines += [f"Automatic pivots: {r.pivots_run} run, {r.pivots_skipped} skipped (see the case's Pivot Log).", ""]
    lines += ["## Coverage gaps", ""]
    # Coverage gaps are the platform's own text (tool names, run numbers), not user input.
    lines += [f"- {g}" for g in r.coverage_gaps] or ["None: every tool's latest run completed."]
    lines += [
        "",
        "## Method",
        "",
        "- **Source reliability** rates the class of source (Admiralty scale), independently of identity confidence: "
        + "; ".join(f"{k} = {v.lower()}" for k, v in r.reliability_scale.items())
        + ".",
        "- **Confidence** combines the source's prior, independent corroborating sources, cross-field links and "
        "context-tag matches. Only identical identifiers are merged automatically; identity matches are reviewed "
        "by an analyst.",
        "- Tools whose output could not be verified as a complete run are reported as failures, never as "
        '"nothing found".',
        "",
    ]
    return "\n".join(lines)
