"""The case report as a document model, shared by every export format.

PDF, Word, HTML, Markdown and plain text all render from the same ``Doc``, so they say
the same thing in the same order. It is organised for its readers:

* **Summary** (decision makers): the analyst's conclusion, the numbers, the strongest
  findings and the caveats, on one page.
* **Findings and connections** (investigators): everything, grouped by kind, with how
  strongly each one is believed and why.
* **Method, authorisation and evidence** (legal, compliance, audit): the basis for the
  work, how scores and grades are meant, which tools ran, and the captured pages with
  their fingerprints.

Tool output is messy: long URLs, stray whitespace, control characters, values hundreds of
characters long. ``clean`` and ``url_parts`` make it readable without changing what it
says; the raw-data text export keeps every value whole.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import brand
from app.correlation.engine import NOT_SAME, POSSIBLE_SAME, SAME_AS
from app.models import (
    SOURCE_RELIABILITY,
    Entity,
    EntityObservation,
    Investigation,
    Relation,
    Snapshot,
    Target,
    User,
)
from app.services.report import build_report

CLASSIFICATION = "TLP:AMBER"
HANDLING = "Contains personal data. Share only with people who need it for this case."
SCOPES = {
    "visible": "All findings except those ruled out",
    "confirmed": "Targets and confirmed findings only",
    "all": "Every finding, including those ruled out",
}
DETAILS = {"full": "Full report", "brief": "Brief"}
KEY_FINDINGS = 8
BRIEF_PER_GROUP = 10

TYPE_LABELS = {
    "account": "Accounts", "username": "Usernames", "email": "Email addresses", "name": "Names",
    "domain": "Domains", "hostname": "Hostnames", "ip": "IP addresses", "phone": "Phone numbers",
    "registration": "Registrations", "breach": "Breach records", "web_mention": "Web mentions",
    "image": "Images", "location": "Locations",
}  # fmt: skip
TYPE_ORDER = list(TYPE_LABELS)
STRENGTHS = {
    "target": "Target", "confirmed": "Confirmed", "likely": "Likely", "possible": "Possible",
    "unlikely": "Unlikely", "ruled_out": "Ruled out",
}  # fmt: skip
STRENGTH_MEANING = {
    "target": "An identifier the case started from.",
    "confirmed": "An analyst decided it belongs to the subject.",
    "likely": "Strong, independent evidence ties it to the subject.",
    "possible": "Some evidence ties it to the subject; not enough to rely on alone.",
    "unlikely": "Little ties it to the subject; kept for completeness.",
    "ruled_out": "An analyst decided it does not belong to the subject.",
}
BASIS = {
    "analyst": ("Decided by an analyst", "A person reviewed the evidence and recorded this link."),
    "observed": ("Observed", "A tool reported it, or a fetched page shows it."),
    "rule": ("Rule match", "Two values match by a fixed rule. This connects values, not people."),
    "similarity": ("Similarity", "Two values look alike. This suggests a connection; it does not establish one."),
    "imported": ("Imported", "Came in a file from elsewhere and was never observed by this platform."),
}
BASIS_ORDER = ["analyst", "observed", "rule", "similarity", "imported"]

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏  ﻿]")


def clean(value, limit: int = 300) -> str:
    """Readable text from tool output: no control characters, one space between words, a sane length."""
    text = " ".join(_CONTROL.sub("", str(value or "")).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def url_parts(value: str) -> tuple[str, str] | None:
    """(host, rest) for an http(s) URL, the rest shortened in the middle, or None for anything else."""
    if not re.match(r"^https?://", value or "", re.I):
        return None
    u = urlparse(value)
    host = (u.hostname or "").removeprefix("www.")
    rest = u.path.rstrip("/") + (f"?{u.query}" if u.query else "")
    if len(rest) > 48:
        rest = rest[:30] + "…" + rest[-15:]
    return host, rest


def safe_href(value: str | None) -> str | None:
    return value if value and re.match(r"^https?://[^\s\"'<>]+$", value, re.I) else None


@dataclass
class F:
    """One finding, ready to print."""

    id: str
    type: str
    type_label: str
    value: str  # full, cleaned
    short: str  # for tables
    host: str | None
    path: str | None
    href: str | None
    strength: str
    strength_label: str
    score: float
    grade: str
    grade_text: str
    sources: list[str]
    first_seen: datetime
    last_seen: datetime
    merged: int = 0
    imported: bool = False
    page_check: str | None = None
    details: list[tuple[str, str]] = field(default_factory=list)  # profile name, location, ...
    raw_value: str = ""


@dataclass
class C:
    """One connection between two findings."""

    a: str
    b: str
    directed: bool
    label: str
    why: str
    confidence: float | None
    tool: str
    basis: str
    first_seen: datetime | None


@dataclass
class Doc:
    case: Investigation
    ref: str
    generated_at: datetime
    generated_by: str
    scope: str
    detail: str
    assessment: list[str]
    assessment_updated_at: datetime | None
    authorization: list[str]
    lawful_basis_at: datetime | None
    targets: list[tuple[str, str, list[str]]]
    stats: dict[str, int]
    key: list[F]
    groups: list[tuple[str, list[F], int]]  # label, findings shown, how many more there are
    connections: list[tuple[str, str, str, list[C]]]  # basis, label, meaning, links
    contradictions: list[tuple[str, str]]
    gaps: list[str]
    pending_suggestions: int
    scans: list[dict]
    diff_summary: str | None
    pivots: tuple[int, int]
    tools: list[str]
    snapshots: list[dict]
    highlights: list[tuple[str, str]]  # pinned on the working log: what, why
    caveats: list[str]
    grades: dict[str, str] = field(default_factory=lambda: SOURCE_RELIABILITY)
    strengths: dict[str, str] = field(default_factory=lambda: STRENGTH_MEANING)
    product: str = brand.NAME
    descriptor: str = brand.DESCRIPTOR
    classification: str = CLASSIFICATION
    handling: str = HANDLING

    @property
    def title(self) -> str:
        return clean(self.case.name, 160)

    @property
    def brief(self) -> bool:
        return self.detail == "brief"

    @property
    def scope_label(self) -> str:
        return SCOPES[self.scope]

    @property
    def all_findings(self) -> list[F]:
        return [f for _, rows, _ in self.groups for f in rows]


def _strength(e: Entity) -> str:
    from app.services.entities import LIKELY, POSSIBLE

    if e.is_seed:
        return "target"
    if e.dismissed_flag:
        return "ruled_out"
    if e.confirmed_flag:
        return "confirmed"
    return "likely" if e.confidence >= LIKELY else "possible" if e.confidence >= POSSIBLE else "unlikely"


_RANK = {"target": 0, "confirmed": 1, "likely": 2, "possible": 3, "unlikely": 4, "ruled_out": 5}
_PAGE = {"verified": "Profile page checked", "unverified": "Page could not be checked", "rejected": "Page check failed"}


def _details(e: Entity) -> list[tuple[str, str]]:
    a = e.attributes or {}
    profile = a.get("profile") if isinstance(a.get("profile"), dict) else {}
    out = []
    for key, label in (("fullname", "Name"), ("name", "Name"), ("location", "Location"), ("country", "Country"),
                       ("bio", "Bio"), ("created", "Account created")):  # fmt: skip
        v = profile.get(key)
        if v and label not in {k for k, _ in out}:
            out.append((label, clean(v, 160)))
    if a.get("site") and e.type != "account":
        out.append(("Site", clean(a["site"], 80)))
    if a.get("breach") or a.get("breach_name"):
        out.append(("Breach", clean(a.get("breach") or a.get("breach_name"), 120)))
    if a.get("imported_from"):
        out.append(("Imported from", clean(a["imported_from"], 120)))
    return out


def _finding(e: Entity, sources: list[str], merged: int) -> F:
    value = clean(e.value, 2000)
    href = safe_href((e.attributes or {}).get("url") or (e.value if e.type in ("account", "web_mention") else None))
    parts = url_parts(href or value) if e.type in ("account", "web_mention", "image") else None
    strength = _strength(e)
    return F(
        id=str(e.id), type=e.type, type_label=TYPE_LABELS.get(e.type, e.type.replace("_", " ").title()),
        value=value, short=clean(e.value, 90), host=parts[0] if parts else None, path=parts[1] if parts else None,
        href=href, strength=strength, strength_label=STRENGTHS[strength], score=round(e.confidence, 2),
        grade=e.source_reliability, grade_text=SOURCE_RELIABILITY.get(e.source_reliability, ""),
        sources=sources, first_seen=e.first_seen, last_seen=e.last_verified, merged=merged,
        imported=sources == ["import"], page_check=_PAGE.get(e.verification or ""), details=_details(e),
        raw_value=e.value,
    )  # fmt: skip


async def build_document(
    session: AsyncSession, case: Investigation, user: User, scope: str = "visible", detail: str = "full"
) -> Doc:
    """Everything a report export needs. The case must already have its assessment."""
    scope = scope if scope in SCOPES else "visible"
    detail = detail if detail in DETAILS else "full"
    report = await build_report(session, case, user)
    entities = list((await session.scalars(select(Entity).where(Entity.case_id == case.id))).all())
    owner = {e.id: (e.merged_into_id or e.id) for e in entities}
    merged: dict[uuid.UUID, int] = defaultdict(int)
    sources: dict[uuid.UUID, set[str]] = defaultdict(set)
    for e in entities:
        sources[owner[e.id]].add(e.source_tool)
        if e.merged_into_id:
            merged[e.merged_into_id] += 1
    rows = await session.execute(
        select(EntityObservation.entity_id, EntityObservation.source_tool).where(
            EntityObservation.entity_id.in_(list(owner))
        )
    ) if owner else []  # fmt: skip
    for eid, tool in rows:
        sources[owner[eid]].add(tool)

    live = [e for e in entities if e.merged_into_id is None]
    if scope == "confirmed":
        chosen = [e for e in live if e.is_seed or e.confirmed_flag]
    elif scope == "visible":
        chosen = [e for e in live if not e.dismissed_flag]
    else:
        chosen = live
    chosen.sort(key=lambda e: (_RANK[_strength(e)], -e.confidence, e.type, e.value.casefold()))
    findings = [_finding(e, sorted(sources[e.id]), merged[e.id]) for e in chosen]
    by_id = {f.id: f for f in findings}

    grouped: dict[str, list[F]] = defaultdict(list)
    for f in findings:
        grouped[f.type].append(f)
    order = sorted(grouped, key=lambda t: (TYPE_ORDER.index(t) if t in TYPE_ORDER else 99, t))
    groups = []
    for t in order:
        rows_ = grouped[t]
        keep = rows_[:BRIEF_PER_GROUP] if detail == "brief" else rows_
        groups.append((rows_[0].type_label, keep, len(rows_) - len(keep)))

    counts = defaultdict(int)
    for e in live:
        counts[_strength(e)] += 1
    rels = (await session.scalars(select(Relation).where(Relation.case_id == case.id))).all()
    shown_rels = [r for r in rels if r.relation_type not in (SAME_AS, NOT_SAME, POSSIBLE_SAME)
                  and str(owner.get(r.entity_a_id)) in by_id and str(owner.get(r.entity_b_id)) in by_id
                  and owner.get(r.entity_a_id) != owner.get(r.entity_b_id)]  # fmt: skip
    stats = {
        "confirmed": counts["confirmed"], "likely": counts["likely"], "possible": counts["possible"],
        "unlikely": counts["unlikely"], "ruled_out": counts["ruled_out"], "targets": counts["target"],
        "findings": sum(v for k, v in counts.items() if k not in ("target", "ruled_out")),
        "links": len(shown_rels), "scans": len(report.runs),
        "sources": len({s for f in findings for s in f.sources} - {"analyst"}),
    }  # fmt: skip

    key = [f for f in findings if f.strength in ("confirmed", "likely")][:KEY_FINDINGS]

    seen_pairs: set[tuple] = set()
    by_basis: dict[str, list[C]] = defaultdict(list)
    for r in sorted(shown_rels, key=lambda r: (-(r.confidence or 0), r.created_at)):
        a, b = by_id[str(owner[r.entity_a_id])], by_id[str(owner[r.entity_b_id])]
        pair = (a.id, b.id, r.relation_type)
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        by_basis[r.basis].append(C(a.short, b.short, r.directed, r.relation_type.replace("_", " "),
                                   clean(r.match_explanation, 200), r.confidence, r.source_tool, r.basis,
                                   r.created_at))  # fmt: skip
    connections = []
    for basis in BASIS_ORDER:
        if by_basis.get(basis):
            links = by_basis[basis][:25] if detail == "brief" else by_basis[basis]
            connections.append((basis, *BASIS[basis], links))

    snaps = (
        await session.scalars(select(Snapshot).where(Snapshot.case_id == case.id).order_by(Snapshot.created_at))
    ).all()
    snapshots = [
        {"finding": by_id[str(owner.get(s.entity_id))].short if str(owner.get(s.entity_id)) in by_id else "—",
         "url": clean(s.final_url or s.url, 200), "status": s.status_code, "at": s.created_at, "sha256": s.sha256,
         "size": s.size}
        for s in snaps
    ]  # fmt: skip

    from app.services.worklog import worklog

    log = await worklog(session, case.id)
    highlights = []
    for p in log.pins:
        if p.entity is not None:
            what = f"{p.entity.type.replace('_', ' ').capitalize()}: {clean(p.entity.value, 90)}"
        elif p.relation is not None:
            a, b = p.ends
            what = f"Link: {clean(a.value if a else '?', 60)} — {clean(b.value if b else '?', 60)}"
        else:
            continue
        highlights.append((what, clean(p.note.body, 300)))

    caveats = []
    if report.pending_suggestions:
        caveats.append(f"{report.pending_suggestions} possible duplicate(s) have not been reviewed by an analyst.")
    if report.coverage_gaps:
        caveats.append(f"{len(report.coverage_gaps)} tool(s) failed in their latest run; their findings may be "
                       "incomplete.")  # fmt: skip
    if report.contradictions:
        caveats.append(f"{len(report.contradictions)} contradiction(s) between sources are flagged below.")
    if any(f.imported for f in findings):
        caveats.append("Some findings were imported from a file and never observed by this platform.")
    if stats["ruled_out"] and scope != "all":
        caveats.append(f"{stats['ruled_out']} finding(s) the analyst ruled out are not listed.")

    targets = (await session.scalars(select(Target).where(Target.case_id == case.id))).all()
    now = datetime.now(UTC)
    ref = hashlib.sha256(f"{case.id}:{now.isoformat()}".encode()).hexdigest()[:10].upper()
    tools = sorted({t for run in report.runs for t in run.tools_included} - {"import"})
    return Doc(
        case=case, ref=f"{ref[:5]}-{ref[5:]}", generated_at=now, generated_by=user.email, scope=scope, detail=detail,
        assessment=[p.strip() for p in re.split(r"\n\s*\n", (case.analyst_assessment or "").strip()) if p.strip()],
        assessment_updated_at=case.analyst_assessment_updated_at,
        authorization=[p.strip() for p in (case.authorization_note or "").strip().splitlines() if p.strip()],
        lawful_basis_at=case.lawful_basis_confirmed_at,
        targets=[(t.type, clean(t.value, 200), list(t.context_tags or [])) for t in targets],
        stats=stats, key=key, groups=groups, connections=connections,
        contradictions=[(clean(x.title, 120), clean(x.detail, 400)) for x in report.contradictions],
        gaps=report.coverage_gaps, pending_suggestions=report.pending_suggestions,
        scans=[{"number": r.run_number, "trigger": {"manual": "Analyst", "watch_mode": "Watch mode",
                "pivot_chain": "Follow-up", "import": "Import"}.get(r.triggered_by, r.triggered_by),
                "status": r.status, "at": r.started_at or r.created_at, "tools": len(r.tools_included),
                "failed": list(r.tools_failed or [])} for r in report.runs],
        diff_summary=report.diff_summary, pivots=(report.pivots_run, report.pivots_skipped), tools=tools,
        snapshots=snapshots, highlights=highlights, caveats=caveats,
    )  # fmt: skip
