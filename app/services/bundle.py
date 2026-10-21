"""The evidence bundle: one ZIP that hands a case over with everything needed to check it.

    README.txt            what is inside and how to verify it
    manifest.json         every other file with its SHA-256 and size
    report.md             the assessment-led report
    case.json             findings, decisions and links (the JSON export, all findings)
    case.stix.json        the same as a STIX 2.1 bundle (TLP:AMBER)
    provenance.json       every sighting of every finding, and every link with its evidence
    audit.json            the case's audit trail: who did what, when, from where
    worklog.json          the analysts' working log and what they pinned, in order
    snapshots.json        captured pages: URL, status, when, by whom, SHA-256, intact or not
    snapshots/<sha256>    the captured bytes, exactly as received

The manifest's own SHA-256 is printed in the README and sent as a response header, so a
recipient can record it at hand-over and later show the bundle was not changed.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import brand
from app.models import AccessLog, Entity, EntityObservation, Investigation, Relation, ScanRun, Snapshot, User

FORMAT = "unmask-evidence-bundle"
VERSION = 1


def _iso(dt: datetime | None) -> str | None:
    return dt.isoformat() if dt else None


def _json(data) -> bytes:
    return json.dumps(data, indent=2, ensure_ascii=False, default=str).encode()


async def _provenance(session: AsyncSession, case: Investigation) -> dict:
    entities = (await session.scalars(select(Entity).where(Entity.case_id == case.id))).all()
    by_id = {e.id: e for e in entities}
    runs = {
        r.id: r.run_number for r in (await session.scalars(select(ScanRun).where(ScanRun.case_id == case.id))).all()
    }
    obs = (
        await session.scalars(
            select(EntityObservation)
            .where(EntityObservation.entity_id.in_(list(by_id)))
            .order_by(EntityObservation.observed_at)
        )
    ).all() if by_id else []  # fmt: skip
    sightings: dict[str, list] = {}
    for o in obs:
        parent = by_id.get(o.parent_entity_id) if o.parent_entity_id else None
        sightings.setdefault(str(o.entity_id), []).append({
            "tool": o.source_tool, "scan": runs.get(o.scan_run_id), "observed_at": _iso(o.observed_at),
            "searched_from": parent.value if parent else None, "source_url": o.source_url,
            "source_grade": o.reliability, "reported": o.reported, "details_sha256": o.attributes_digest,
        })  # fmt: skip
    findings = [
        {"id": str(e.id), "type": e.type, "value": e.value, "target": e.is_seed, "confirmed": e.confirmed_flag,
         "ruled_out": e.dismissed_flag, "merged_into": str(e.merged_into_id) if e.merged_into_id else None,
         "score": e.confidence, "score_explanation": (e.attributes or {}).get("_score_explanation"),
         "first_seen": _iso(e.first_seen), "sightings": sightings.get(str(e.id), [])}
        for e in entities
    ]  # fmt: skip
    rels = (await session.scalars(select(Relation).where(Relation.case_id == case.id))).all()
    links = [
        {"id": str(r.id), "from": str(r.entity_a_id), "to": str(r.entity_b_id), "type": r.relation_type,
         "directed": r.directed, "basis": r.basis, "by": r.created_by, "tool": r.source_tool,
         "confidence": r.confidence, "why": r.match_explanation, "first_seen": _iso(r.created_at),
         "last_seen": _iso(r.last_seen), "times_seen": r.seen_count}
        for r in rels
    ]  # fmt: skip
    return {"findings": findings, "links": links,
            "basis": {"observed": "a tool reported it or a fetched page shows it", "rule": "a fixed string rule",
                      "similarity": "values look alike; not proof", "analyst": "a person decided it"}}  # fmt: skip


async def _audit(session: AsyncSession, case: Investigation) -> list[dict]:
    rows = (
        await session.execute(
            select(AccessLog, User.email)
            .outerjoin(User, User.id == AccessLog.user_id)
            .where(AccessLog.case_id == case.id)
            .order_by(AccessLog.timestamp)
        )
    ).all()
    return [
        {"at": _iso(a.timestamp), "action": a.action, "by": email, "ip": a.ip, "detail": a.detail} for a, email in rows
    ]


async def _worklog(session: AsyncSession, case: Investigation) -> dict:
    from app.services.worklog import worklog

    log = await worklog(session, case.id)
    pins = [
        {"at": _iso(p.note.created_at), "by": log.authors.get(p.note.author_id), "why": p.note.body,
         "finding": str(p.entity.id) if p.entity else None, "link": str(p.relation.id) if p.relation else None}
        for p in log.pins
    ]  # fmt: skip
    entries = [{"at": _iso(n.created_at), "by": log.authors.get(n.author_id), "text": n.body} for n in log.entries]
    return {"entries": entries, "pinned": pins}


async def build_bundle(session: AsyncSession, case: Investigation, user: User) -> tuple[bytes, str]:
    """(zip bytes, SHA-256 of the manifest). The case must already have its assessment."""
    from app.services.evidence import snapshot_body, snapshot_intact
    from app.services.exports import export_json, export_stix
    from app.services.report import build_report, render_markdown

    now = datetime.now(UTC)
    files: dict[str, bytes] = {
        "report.md": render_markdown(await build_report(session, case, user)).encode(),
        "case.json": _json(await export_json(session, case, "all")),
        "case.stix.json": _json(await export_stix(session, case, "all")),
        "provenance.json": _json(await _provenance(session, case)),
        "audit.json": _json(await _audit(session, case)),
        "worklog.json": _json(await _worklog(session, case)),
    }
    snaps = (
        await session.scalars(select(Snapshot).where(Snapshot.case_id == case.id).order_by(Snapshot.created_at))
    ).all()
    emails = {u.id: u.email for u in (await session.scalars(select(User))).all()} if snaps else {}
    meta = []
    for s in snaps:
        name = f"snapshots/{s.sha256}"
        files[name] = snapshot_body(s)
        meta.append({"file": name, "url": s.url, "final_url": s.final_url, "status": s.status_code,
                     "content_type": s.content_type, "captured_at": _iso(s.created_at),
                     "captured_by": emails.get(s.captured_by), "sha256": s.sha256, "size": s.size,
                     "truncated": s.truncated, "intact": snapshot_intact(s), "finding": str(s.entity_id)})  # fmt: skip
    files["snapshots.json"] = _json(meta)
    manifest = {
        "format": FORMAT, "version": VERSION, "product": brand.NAME, "case": {"id": str(case.id), "name": case.name},
        "generated_at": now.isoformat(), "generated_by": user.email,
        "files": [{"name": n, "sha256": hashlib.sha256(b).hexdigest(), "size": len(b)}
                  for n, b in sorted(files.items())],
    }  # fmt: skip
    manifest_bytes = _json(manifest)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    readme = f"""{brand.NAME} evidence bundle
Case: {case.name} ({case.id})
Generated {now:%Y-%m-%d %H:%M} UTC by {user.email}

Manifest SHA-256: {digest}

Record the manifest hash when you receive this bundle. To check it later:
  sha256sum manifest.json            (must match the hash above)
  sha256sum <file>                   (must match that file's entry in manifest.json)

report.md is the analyst's assessment and the evidence behind it. provenance.json shows,
for every finding, each tool that reported it, when, from what, and what it said; and for
every link, how it was established. Links marked "rule" or "similarity" connect values,
not people. audit.json is the case's audit trail. snapshots/ holds captured pages exactly
as received; their SHA-256 values are in snapshots.json and in the file names.

Handle this bundle as the case itself: it contains personal data collected under the
authorisation recorded in report.md.
"""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.txt", readme)
        z.writestr("manifest.json", manifest_bytes)
        for name, body in sorted(files.items()):
            z.writestr(name, body)
    return buf.getvalue(), digest
