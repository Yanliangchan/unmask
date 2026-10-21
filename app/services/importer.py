"""Importing findings from elsewhere: a STIX 2.1 bundle, or an UNMASK case export.

Imported data is a lead, not evidence. Everything it brings in is marked as imported and
never as observed:

* findings come in with source "import", source grade F (reliability cannot be judged) and
  a low starting score (``PRIOR``); they are never page-checked on the way in;
* links come in with basis "imported" and a relation type that never counts as
  corroboration, so a file cannot raise anyone's score by asserting connections;
* nothing is attached to the case's targets: an imported finding was not found from them.

Parsing is strict. Every value is validated for its type; objects and fields this importer
does not understand are reported back, never silently dropped, and the analyst sees the
full report before anything is written (``check`` first, then ``commit`` with the same
plan, carried between the two steps encrypted so it can't be altered in the browser).
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import crypto
from app.adapters.base import EntityCandidate
from app.models import Entity, Investigation, Relation, ScanRun, User

MAX_BYTES = 5 * 1024 * 1024
MAX_FINDINGS = 2000
MAX_VALUE = 512
PRIOR = 0.2
TOOL = "import"
LINK_TYPE = "imported_link"

_EMAIL = re.compile(r"^[^@\s]{1,64}@[a-z0-9.-]+\.[a-z]{2,24}$", re.I)
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)
_HANDLE = re.compile(r"^[\w.\-@+]{1,100}$")
_PHONE = re.compile(r"^\+?[\d\s().\-]{7,24}$")
_URL = re.compile(r"^https?://[^\s<>\"]{4,2000}$", re.I)

# STIX properties every object may carry: read or deliberately ignored, never "unsupported".
_COMMON = {"type", "id", "spec_version", "created", "modified", "created_by_ref", "revoked", "labels", "lang",
           "external_references", "object_marking_refs", "granular_markings", "extensions", "defanged",
           "confidence"}  # fmt: skip
_KNOWN = {
    "email-addr": {"value", "display_name", "belongs_to_ref"},
    "domain-name": {"value", "resolves_to_refs"},
    "ipv4-addr": {"value", "resolves_to_refs", "belongs_to_refs"},
    "ipv6-addr": {"value", "resolves_to_refs", "belongs_to_refs"},
    "url": {"value"},
    "user-account": {"account_login", "account_type", "user_id", "display_name"},
    "identity": {"name", "identity_class", "description", "roles", "sectors", "contact_information"},
    "relationship": {"relationship_type", "source_ref", "target_ref", "description", "start_time", "stop_time"},
    "grouping": {"name", "context", "object_refs", "description"},
    "marking-definition": {"definition_type", "definition", "name"},
    "note": {"abstract", "content", "authors", "object_refs"},
}
# Container and marking objects: understood, but there is nothing in them to import.
_STRUCTURAL = {"grouping", "marking-definition", "note"}


@dataclass
class Item:
    ref: str  # the id in the source file, for links and the report
    type: str
    value: str
    url: str | None = None
    site: str | None = None


@dataclass
class Link:
    a: str
    b: str
    label: str


@dataclass
class Plan:
    format: str
    filename: str
    items: list[Item] = field(default_factory=list)
    links: list[Link] = field(default_factory=list)
    invalid: list[dict] = field(default_factory=list)  # {"ref", "type", "reason"}
    unsupported_objects: dict[str, int] = field(default_factory=dict)  # STIX type -> count
    ignored_fields: dict[str, list[str]] = field(default_factory=dict)  # object type -> field names
    dropped_links: int = 0
    duplicates: int = 0

    @property
    def counts(self) -> dict[str, int]:
        return dict(Counter(i.type for i in self.items))

    def seal(self) -> str:
        return crypto.encrypt(json.dumps(asdict(self), separators=(",", ":")))

    @classmethod
    def unseal(cls, token: str) -> Plan:
        raw = json.loads(crypto.decrypt(token))
        return cls(raw["format"], raw["filename"], [Item(**i) for i in raw["items"]], [Link(**x) for x in raw["links"]],
                   raw["invalid"], raw["unsupported_objects"], raw["ignored_fields"], raw["dropped_links"],
                   raw["duplicates"])  # fmt: skip


class ImportError_(ValueError):
    """The file can't be read as a supported format at all."""


def _validate(kind: str, value) -> tuple[str | None, str | None]:
    """(clean value, None) or (None, why it was refused)."""
    if not isinstance(value, str) or not value.strip():
        return None, "no value"
    v = " ".join(value.split())
    if len(v) > MAX_VALUE:
        return None, f"longer than {MAX_VALUE} characters"
    if kind == "email":
        return (v.lower(), None) if _EMAIL.match(v) else (None, "not an email address")
    if kind == "domain":
        v = v.lower().rstrip(".")
        return (v, None) if _DOMAIN.match(v) else (None, "not a domain name")
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v)), None
        except ValueError:
            return None, "not an IP address"
    if kind == "username":
        return (v, None) if _HANDLE.match(v) else (None, "not a plausible username")
    if kind == "account":
        return (v, None) if _URL.match(v) else (None, "an account must be a profile URL")
    if kind == "phone":
        return (v, None) if _PHONE.match(v) and sum(c.isdigit() for c in v) >= 7 else (None, "not a phone number")
    if kind == "web_mention":
        return (v, None) if _URL.match(v) else (None, "not an http(s) URL")
    if kind == "name":
        return (v, None) if 1 < len(v) <= 200 and not re.search(r"[<>{}]", v) else (None, "not a plausible name")
    return None, f"type {kind} can't be imported"


def _stix_item(obj: dict) -> tuple[Item | None, str | None]:
    t, ref = obj.get("type"), str(obj.get("id", ""))
    if t == "email-addr":
        kind, raw = "email", obj.get("value")
    elif t == "domain-name":
        kind, raw = "domain", obj.get("value")
    elif t in ("ipv4-addr", "ipv6-addr"):
        kind, raw = "ip", obj.get("value")
    elif t == "url":
        kind, raw = "web_mention", obj.get("value")
    elif t == "user-account":
        # An account is a profile URL here; without one, the login is imported as a username.
        site = obj.get("account_type") or obj.get("x_unmask_site")
        site = site[:100] if isinstance(site, str) else None
        login, why = _validate("username", obj.get("account_login") or obj.get("user_id"))
        if login is None:
            return None, why
        url = obj.get("x_unmask_profile_url")
        if isinstance(url, str) and _URL.match(url):
            return Item(ref, "account", url, url, site), None
        return Item(ref, "username", login, None, site), None
    elif t == "identity":
        if obj.get("identity_class", "individual") != "individual":
            return None, "identity is not an individual"
        kind, raw = "name", obj.get("name")
    else:
        return None, None
    value, why = _validate(kind, raw)
    return (Item(ref, kind, value), None) if value else (None, why)


def _from_stix(data: dict, plan: Plan) -> None:
    objects = data.get("objects")
    if not isinstance(objects, list):
        raise ImportError_("a STIX bundle needs an 'objects' list")
    ignored: dict[str, set] = defaultdict(set)
    unsupported: Counter = Counter()
    rels = []
    for obj in objects:
        if not isinstance(obj, dict) or not isinstance(obj.get("type"), str):
            plan.invalid.append({"ref": "?", "type": "?", "reason": "not a STIX object"})
            continue
        t = obj["type"]
        if t not in _KNOWN:
            unsupported[t] += 1
            continue
        extra = {k for k in obj if k not in _COMMON and k not in _KNOWN[t] and not k.startswith("x_unmask_")}
        if extra:
            ignored[t] |= extra
        if t == "relationship":
            rels.append(obj)
            continue
        if t in _STRUCTURAL:
            continue
        item, why = _stix_item(obj)
        if item is not None:
            plan.items.append(item)
        elif why:
            plan.invalid.append({"ref": str(obj.get("id", "?")), "type": t, "reason": why})
    for r in rels:
        a, b = r.get("source_ref"), r.get("target_ref")
        label = str(r.get("relationship_type") or "related-to")[:60]
        plan.links.append(Link(str(a), str(b), label))
    plan.unsupported_objects = dict(unsupported)
    plan.ignored_fields = {k: sorted(v) for k, v in ignored.items()}


_UNMASK_TYPES = {"email", "domain", "hostname", "ip", "username", "account", "phone", "name", "web_mention"}
_UNMASK_FIELDS = {"id", "type", "value", "decision", "not_them_reason", "confidence", "source_reliability",
                  "page_check", "sources", "merged_duplicates", "first_seen", "last_seen", "attributes"}  # fmt: skip
# What an export says about a finding (scores, decisions, page checks) is someone else's
# judgement. It is reported as ignored, never carried over.
_JUDGEMENTS = ["confidence", "decision", "not_them_reason", "page_check", "source_reliability", "sources"]


def _from_unmask(data: dict, plan: Plan) -> None:
    findings = data.get("findings")
    if not isinstance(findings, list):
        raise ImportError_("an UNMASK export needs a 'findings' list")
    ignored: set[str] = set()
    for f in findings:
        if not isinstance(f, dict):
            plan.invalid.append({"ref": "?", "type": "?", "reason": "not a finding"})
            continue
        ignored |= {k for k in f if k not in _UNMASK_FIELDS}
        ignored |= {k for k in _JUDGEMENTS if f.get(k) not in (None, [], "")}
        kind, ref = f.get("type"), str(f.get("id", "?"))
        if kind not in _UNMASK_TYPES:
            plan.invalid.append({"ref": ref, "type": str(kind), "reason": f"type {kind} can't be imported"})
            continue
        kind = "domain" if kind == "hostname" else kind
        value, why = _validate(kind, f.get("value"))
        if value is None:
            plan.invalid.append({"ref": ref, "type": kind, "reason": why})
            continue
        attrs = f.get("attributes") if isinstance(f.get("attributes"), dict) else {}
        url = attrs.get("url") if isinstance(attrs.get("url"), str) and _URL.match(attrs["url"]) else None
        site = attrs.get("site") if isinstance(attrs.get("site"), str) else None
        plan.items.append(Item(ref, kind, value, url, site[:100] if site else None))
    for x in data.get("links") or []:
        if isinstance(x, dict):
            plan.links.append(Link(str(x.get("from")), str(x.get("to")), str(x.get("type") or "related")[:60]))
    plan.ignored_fields = {"finding": sorted(ignored)} if ignored else {}


def check(raw: bytes, filename: str) -> Plan:
    """Parse and validate a file; write nothing. Raises ImportError_ if it can't be read at all."""
    if len(raw) > MAX_BYTES:
        raise ImportError_(f"the file is larger than {MAX_BYTES // (1024 * 1024)} MB")
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ImportError_(f"not valid JSON ({exc.__class__.__name__})") from None
    if not isinstance(data, dict):
        raise ImportError_("expected a JSON object")
    name = re.sub(r"[^\w.\- ]", "_", filename or "upload.json")[:120]
    if data.get("type") == "bundle":
        plan = Plan("STIX 2.1 bundle", name)
        _from_stix(data, plan)
    elif data.get("format") == "unmask-case-export":
        plan = Plan("UNMASK case export", name)
        _from_unmask(data, plan)
    else:
        raise ImportError_("not a STIX 2.1 bundle or an UNMASK case export")
    # One finding per (type, value); links only between findings that made it in.
    seen: dict[tuple[str, str], Item] = {}
    alias: dict[str, str] = {}
    unique = []
    for item in plan.items:
        key = (item.type, item.value.casefold())
        if key in seen:
            plan.duplicates += 1
            alias[item.ref] = seen[key].ref
            continue
        seen[key] = item
        unique.append(item)
    if len(unique) > MAX_FINDINGS:
        raise ImportError_(f"more than {MAX_FINDINGS} findings in one file; split it")
    plan.items = unique
    refs = {i.ref for i in unique}
    links, pairs = [], set()
    for x in plan.links:
        a, b = alias.get(x.a, x.a), alias.get(x.b, x.b)
        if a not in refs or b not in refs or a == b or (a, b) in pairs:
            plan.dropped_links += 1
            continue
        pairs.add((a, b))
        links.append(Link(a, b, x.label))
    plan.links = links
    return plan


async def commit(session: AsyncSession, case: Investigation, user: User, plan: Plan) -> ScanRun:
    """Write a checked plan into the case as an 'import' run. Caller commits."""
    from app.services.scans import create_scan_run, persist_candidates

    run = await create_scan_run(session, case, triggered_by="import", jobs=[])
    now = datetime.now(UTC)
    run.status, run.started_at, run.completed_at = "completed", now, now
    run.tools_included, run.tools_completed = [TOOL], [TOOL]
    cands = []
    for item in plan.items:
        attrs = {"origin": "imported", "imported_from": plan.filename, "imported_format": plan.format,
                 "imported_ref": item.ref}  # fmt: skip
        if item.url:
            attrs["url"] = item.url
        if item.site:
            attrs["site"] = item.site
        cands.append(EntityCandidate(item.type, item.value, attrs, "F", PRIOR, {"value": PRIOR}))
    await persist_candidates(session, run=run, parent=None, tool=TOOL, candidates=cands)
    await session.flush()
    by_ref: dict[str, uuid.UUID] = {}
    for item in plan.items:
        e = await session.scalar(
            select(Entity.id)
            .where(
                Entity.case_id == case.id,
                Entity.type == item.type,
                Entity.value_digest == crypto.digest(item.type, item.value),
            )  # fmt: skip
            .order_by(Entity.merged_into_id.is_not(None))
            .limit(1)
        )
        if e:
            by_ref[item.ref] = e
    for x in plan.links:
        a, b = by_ref.get(x.a), by_ref.get(x.b)
        if a and b and a != b:
            session.add(Relation(case_id=case.id, entity_a_id=a, entity_b_id=b, relation_type=LINK_TYPE,
                                 source_tool=TOOL, match_explanation=f"{plan.format}: {x.label}", confidence=None,
                                 basis="imported", directed=False, created_by=TOOL,
                                 scan_run_id=run.id, last_scan_run_id=run.id))  # fmt: skip
    run.failure_details = {"_import": {"file": plan.filename, "format": plan.format, "findings": len(plan.items),
                                       "links": len(plan.links), "invalid": len(plan.invalid)}}  # fmt: skip
    await session.flush()
    return run
