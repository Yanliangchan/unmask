"""Case data exports: CSV for spreadsheets, JSON for scripts, STIX 2.1 for threat-intel platforms.

Exports carry what the analyst sees: findings that weren't ruled out, after
de-duplication, with their scores, decisions and sources. Findings marked
"Not them" are left out unless asked for.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Entity, EntityObservation, Investigation, Relation, Snapshot
from app.services.accuracy import DISMISS_REASONS

SCOPES = ("visible", "confirmed", "all")


@dataclass
class Row:
    entity: Entity
    sources: list[str]
    merged: int


async def _rows(session: AsyncSession, case: Investigation, scope: str) -> list[Row]:
    entities = list((await session.scalars(select(Entity).where(Entity.case_id == case.id))).all())
    owner = {e.id: (e.merged_into_id or e.id) for e in entities}
    sources: dict[uuid.UUID, set[str]] = defaultdict(set)
    merged: dict[uuid.UUID, int] = defaultdict(int)
    for e in entities:
        sources[owner[e.id]].add(e.source_tool)
        if e.merged_into_id:
            merged[e.merged_into_id] += 1
    if owner:
        obs = await session.execute(
            select(EntityObservation.entity_id, EntityObservation.source_tool).where(
                EntityObservation.entity_id.in_(list(owner))
            )
        )
        for eid, tool in obs.all():
            sources[owner[eid]].add(tool)
    keep = []
    for e in entities:
        if e.merged_into_id is not None:
            continue
        if scope == "confirmed" and not (e.confirmed_flag or e.is_seed):
            continue
        if scope != "all" and e.dismissed_flag:
            continue
        keep.append(Row(e, sorted(sources[e.id]), merged[e.id]))
    keep.sort(key=lambda r: (not r.entity.is_seed, not r.entity.confirmed_flag, -r.entity.confidence))
    return keep


def _decision(e: Entity) -> str:
    if e.is_seed:
        return "target"
    if e.confirmed_flag:
        return "confirmed"
    if e.dismissed_flag:
        return "ruled out"
    return "undecided"


def _safe_cell(value) -> str:
    """Stop spreadsheet apps from running a cell as a formula (CSV injection)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


CSV_COLUMNS = ["value", "type", "site", "url", "decision", "not_them_reason", "confidence", "source_reliability",
               "page_check", "sources", "merged_duplicates", "first_seen", "last_seen", "id"]  # fmt: skip


async def export_csv(session: AsyncSession, case: Investigation, scope: str = "visible") -> str:
    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(CSV_COLUMNS)
    for r in await _rows(session, case, scope):
        e, a = r.entity, r.entity.attributes or {}
        w.writerow([_safe_cell(v) for v in (
            e.value, e.type, a.get("site", ""), a.get("url", ""), _decision(e),
            DISMISS_REASONS.get(e.dismiss_reason or "", "") if e.dismissed_flag else "",
            f"{e.confidence:.2f}", e.source_reliability, e.verification or "", "; ".join(r.sources), r.merged,
            e.first_seen.isoformat(), e.last_verified.isoformat(), e.id,
        )])  # fmt: skip
    return out.getvalue()


async def export_json(session: AsyncSession, case: Investigation, scope: str = "visible") -> dict:
    rows = await _rows(session, case, scope)
    ids = {r.entity.id for r in rows}
    rels = (await session.scalars(select(Relation).where(Relation.case_id == case.id))).all()
    snaps = (await session.scalars(select(Snapshot).where(Snapshot.case_id == case.id))).all()
    return {
        "format": "unmask-case-export",
        "version": 1,
        "exported_at": datetime.now(UTC).isoformat(),
        "scope": scope,
        "case": {
            "id": str(case.id),
            "name": case.name,
            "created_at": case.created_at.isoformat(),
            "authorization_note": case.authorization_note,
            "lawful_basis_confirmed_at": case.lawful_basis_confirmed_at.isoformat()
            if case.lawful_basis_confirmed_at
            else None,
            "analyst_assessment": case.analyst_assessment,
            "targets": [{"type": t.type, "value": t.value, "context_tags": t.context_tags} for t in case.targets],
        },
        "findings": [
            {
                "id": str(r.entity.id),
                "type": r.entity.type,
                "value": r.entity.value,
                "decision": _decision(r.entity),
                "not_them_reason": r.entity.dismiss_reason if r.entity.dismissed_flag else None,
                "confidence": round(r.entity.confidence, 4),
                "source_reliability": r.entity.source_reliability,
                "page_check": r.entity.verification,
                "sources": r.sources,
                "merged_duplicates": r.merged,
                "first_seen": r.entity.first_seen.isoformat(),
                "last_seen": r.entity.last_verified.isoformat(),
                "attributes": {k: v for k, v in (r.entity.attributes or {}).items() if not k.startswith("_")},
            }
            for r in rows
        ],
        "links": [
            {
                "from": str(x.entity_a_id),
                "to": str(x.entity_b_id),
                "type": x.relation_type,
                "source": x.source_tool,
                "explanation": x.match_explanation,
                "confidence": x.confidence,
            }
            for x in rels
            if x.entity_a_id in ids and x.entity_b_id in ids
        ],  # fmt: skip
        "snapshots": [
            {
                "finding": str(s.entity_id) if s.entity_id else None,
                "url": s.url,
                "final_url": s.final_url,
                "captured_at": s.created_at.isoformat(),
                "status_code": s.status_code,
                "sha256": s.sha256,
                "bytes": s.size,
            }
            for s in snaps
        ],  # fmt: skip
    }


# --- STIX 2.1 ---------------------------------------------------------------------------------------

# OASIS namespace for deterministic cyber-observable ids (STIX 2.1 §2.9).
STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
# TLP:AMBER (STIX 2.1 predefined marking definition): recipients may share within their organisation.
TLP_AMBER = "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82"


def _stamp(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _sco_id(kind: str, contributing: dict) -> str:
    canonical = json.dumps(contributing, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{kind}--{uuid.uuid5(STIX_NAMESPACE, canonical)}"


def _sdo_id(kind: str, case_id: uuid.UUID, key: str) -> str:
    # Stable across re-exports of the same case, so platforms update instead of duplicating.
    return f"{kind}--{uuid.uuid5(case_id, key)}"


def _observable(e: Entity) -> dict | None:
    a = e.attributes or {}
    v = e.value
    if e.type == "email":
        return {"type": "email-addr", "id": _sco_id("email-addr", {"value": v}), "value": v}
    if e.type in ("domain", "hostname"):
        return {"type": "domain-name", "id": _sco_id("domain-name", {"value": v}), "value": v}
    if e.type == "ip":
        kind = "ipv6-addr" if ":" in v else "ipv4-addr"
        return {"type": kind, "id": _sco_id(kind, {"value": v}), "value": v}
    if e.type == "username":
        return {"type": "user-account", "id": _sco_id("user-account", {"account_login": v}), "account_login": v}
    if e.type == "account":
        login = a.get("username") or v
        site = a.get("site") or a.get("host") or ""
        obj = {"type": "user-account", "account_login": login, "x_unmask_site": site}
        obj["id"] = _sco_id(
            "user-account", {"account_login": login, "account_type": site} if site else {"account_login": login}
        )
        if site:
            obj["account_type"] = site
        if a.get("url"):
            obj["x_unmask_profile_url"] = a["url"]
        return obj
    if e.type in ("web_mention", "image") or v.startswith(("http://", "https://")):
        url = a.get("url") or v
        return {"type": "url", "id": _sco_id("url", {"value": url}), "value": url}
    return None


async def export_stix(session: AsyncSession, case: Investigation, scope: str = "visible") -> dict:
    """A STIX 2.1 bundle: a grouping for the case, observables for findings, identities for people."""
    rows = await _rows(session, case, scope)
    now = _stamp(datetime.now(UTC))
    created = _stamp(case.created_at)
    objects: list[dict] = []
    by_entity: dict[uuid.UUID, str] = {}
    seen: set[str] = set()
    for r in rows:
        e = r.entity
        props = {"x_unmask_confidence": round(e.confidence, 4), "x_unmask_decision": _decision(e),
                 "x_unmask_source_reliability": e.source_reliability, "x_unmask_sources": r.sources}  # fmt: skip
        obs = _observable(e)
        if obs is not None:
            obj = {"spec_version": "2.1", **obs, **props}
        elif e.type in ("name", "phone"):
            obj = {"type": "identity", "spec_version": "2.1", "id": _sdo_id("identity", case.id, f"{e.type}:{e.id}"),
                   "created": _stamp(e.first_seen), "modified": _stamp(e.last_verified),
                   "identity_class": "individual", "name": e.value if e.type == "name" else f"Phone {e.value}",
                   "confidence": round(e.confidence * 100), **props}  # fmt: skip
            if e.type == "phone":
                obj["contact_information"] = e.value
        else:
            continue
        by_entity[e.id] = obj["id"]
        if obj["id"] in seen:
            continue
        seen.add(obj["id"])
        objects.append(obj)

    rels = (await session.scalars(select(Relation).where(Relation.case_id == case.id))).all()
    for x in rels:
        src, dst = by_entity.get(x.entity_a_id), by_entity.get(x.entity_b_id)
        if not src or not dst or src == dst:
            continue
        rel = {"type": "relationship", "spec_version": "2.1", "id": _sdo_id("relationship", case.id, str(x.id)),
               "created": _stamp(x.created_at), "modified": _stamp(x.created_at), "relationship_type": "related-to",
               "source_ref": src, "target_ref": dst, "description": x.relation_type.replace("_", " "),
               "x_unmask_relation": x.relation_type}  # fmt: skip
        if x.confidence is not None:
            rel["confidence"] = round(x.confidence * 100)
        objects.append(rel)

    grouping = {
        "type": "grouping", "spec_version": "2.1", "id": _sdo_id("grouping", case.id, "case"),
        "created": created, "modified": now, "name": case.name, "context": "unspecified",
        "description": "Open-source findings exported from an unmask case. Confidence estimates whether a finding "
        "relates to the subject; it is not a conclusion.",
        "object_refs": [o["id"] for o in objects] or [_sdo_id("note", case.id, "empty")],
        "object_marking_refs": [TLP_AMBER],
    }  # fmt: skip
    extra = [grouping]
    if case.analyst_assessment:
        extra.append({"type": "note", "spec_version": "2.1", "id": _sdo_id("note", case.id, "assessment"),
                      "created": created, "modified": now, "abstract": "Analyst assessment",
                      "content": case.analyst_assessment, "object_refs": [grouping["id"]],
                      "object_marking_refs": [TLP_AMBER]})  # fmt: skip
    elif not objects:
        empty = {"type": "note", "spec_version": "2.1", "id": grouping["object_refs"][0], "created": created,
                 "modified": now, "content": "No findings in this export.",
                 "object_refs": [grouping["id"]]}  # fmt: skip
        extra.append(empty)
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": extra + objects}
