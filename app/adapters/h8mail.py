"""h8mail — breach lookups for an email address (subprocess, BSD-3-Clause).

Without API keys h8mail reports every address as "Not Compromised", which is
indistinguishable from a real negative. The adapter therefore refuses to run
until at least one breach source is configured.

Data minimisation: cleartext passwords and hashes are never stored. Only the
fact that a credential was exposed, its kind and a short one-way fingerprint
(keyed HMAC, enough to spot password reuse across breaches) are kept.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from app import crypto
from app.adapters.base import (
    AdapterError,
    EntityCandidate,
    HealthResult,
    RawResult,
    SignatureMismatch,
    ToolAdapter,
    resolve_binary,
    run_tool_subprocess,
    strip_ansi,
    validate_email,
)
from app.config import get_settings

KNOWN_KEYS = {
    "hibp",
    "snusbase_token",
    "leak-lookup_pub",
    "leak-lookup_priv",
    "dehashed_email",
    "dehashed_key",
    "intelx_key",
    "breachdirectory_user",
    "breachdirectory_pass",
    "emailrep",
    "hunterio",
    "weleakinfo_priv",
    "weleakinfo_pub",
}
_CREDENTIAL = re.compile(r"(PASS|HASH|MD5|SALT)")
_ERROR_LINE = re.compile(r"^\[!\]\s*(?P<msg>.+)$")

# Admiralty rating per source family: curated services vs raw dump aggregators.
_RELIABILITY = {"HIBP3": "B", "HUNTER": "C", "EMAILREP": "C", "LEAKLOOKUP": "D"}


def source_reliability(tag: str) -> str:
    for prefix, code in _RELIABILITY.items():
        if tag.startswith(prefix):
            return code
    return "D"


def parse_keys(raw: str) -> dict[str, str]:
    keys = {}
    for pair in raw.split(","):
        if "=" not in pair:
            continue
        name, value = (p.strip() for p in pair.split("=", 1))
        if name in KNOWN_KEYS and value and "\n" not in value:
            keys[name] = value
    return keys


def fingerprint(secret: str) -> str:
    """Keyed (HMAC) and truncated, so it can't be dictionary-attacked back to the secret."""
    return crypto.digest("credential", secret)[:12]


@dataclass
class BreachRecord:
    source_tag: str
    breach: str | None = None
    fields: dict[str, list[str]] = field(default_factory=dict)
    credentials: list[dict[str, str]] = field(default_factory=list)


@dataclass
class H8mailReport:
    email: str
    records: list[BreachRecord]
    source_errors: list[str]


def _record_from_group(items: list[str]) -> list[BreachRecord]:
    """h8mail groups "TAG:value" strings per record, closed by a *_SOURCE tag."""
    records: list[BreachRecord] = []
    current = BreachRecord(source_tag="")
    for item in items:
        tag, _, value = item.partition(":")
        tag, value = tag.strip(), value.strip()
        if not tag:
            continue
        if tag in ("HIBP3", "HIBP3_PASTE", "LEAKLOOKUP_PUB", "WLI_PUB_SRC"):
            # Each of these is a breach name on its own.
            records.append(BreachRecord(source_tag=tag, breach=value))
            continue
        current.source_tag = current.source_tag or tag.split("_", 1)[0]
        if tag.endswith("_SOURCE") or tag.endswith("_EXTSRC"):
            current.breach = value
        elif _CREDENTIAL.search(tag):
            kind = "hash" if re.search("HASH|MD5|SALT", tag) else "password"
            current.credentials.append({"kind": kind, "fingerprint": fingerprint(value)})
        else:
            current.fields.setdefault(tag, []).append(value)
    if current.source_tag:
        records.append(current)
    return records


def parse_output(email: str, stdout: str, report_json: str | None) -> H8mailReport:
    text = strip_ansi(stdout)
    if "Session Recap" not in text:
        raise SignatureMismatch("h8mail did not finish (no session recap)")
    if not report_json:
        raise SignatureMismatch("h8mail wrote no JSON report")
    try:
        data = json.loads(report_json)
        target = next(t for t in data["targets"] if t.get("target", "").lower() == email.lower())
    except (json.JSONDecodeError, KeyError, StopIteration) as exc:
        raise SignatureMismatch("h8mail JSON report does not describe the target") from exc
    errors = [m["msg"].strip() for ln in text.splitlines() if (m := _ERROR_LINE.match(ln.strip()))]
    records = [r for group in target.get("data") or [] for r in _record_from_group(group)]
    if errors and not records:
        raise SignatureMismatch(
            f"{len(errors)} breach source error(s) and no findings — a negative can't be trusted: {errors[0][:160]}"
        )
    return H8mailReport(email=email, records=records, source_errors=errors)


class H8mailAdapter(ToolAdapter):
    name = "h8mail"
    label = "h8mail"
    input_types = ["email"]
    description = "Breach and paste lookups for an email address via configured breach APIs."
    health_check_target = "test@example.com"
    timeout_seconds = 300

    def configured(self) -> str | None:
        if not parse_keys(get_settings().h8mail_keys):
            return "No breach source API key configured (UNMASK_H8MAIL_KEYS)"
        return None

    def build_config(self) -> str:
        lines = ["[h8mail]"] + [f"{k} = {v}" for k, v in sorted(parse_keys(get_settings().h8mail_keys).items())]
        return "\n".join(lines) + "\n"

    def build_argv(self, email: str) -> list[str]:
        email = validate_email(email)
        return [resolve_binary("h8mail"), "-c", "h8mail_config.ini", "-j", "report.json", "-t", email]

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        reason = self.configured()
        if reason:
            raise AdapterError(reason)
        email = validate_email(target_value)
        proc = await run_tool_subprocess(
            self.build_argv(email),
            timeout=self.timeout_seconds,
            files_in={"h8mail_config.ini": self.build_config()},
            collect=["report.json"],
            tool=self.name,
        )
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise AdapterError(f"h8mail exited with code {proc.returncode}: {strip_ansi(tail[0])[:300]}")
        report = parse_output(email, proc.stdout, proc.files.get("report.json"))
        return [RawResult(tool=self.name, target_value=email, payload=report)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        report: H8mailReport = raw.payload
        out: list[EntityCandidate] = []
        for rec in report.records:
            name = rec.breach or rec.source_tag
            reliability = source_reliability(rec.source_tag)
            attrs = {
                "email": report.email,
                "source": rec.source_tag,
                "breach": rec.breach,
                "credential_exposed": bool(rec.credentials),
                "credentials": rec.credentials,
                "fields": rec.fields,
            }
            if report.source_errors:
                attrs["warning"] = "some breach sources errored during this lookup"
            out.append(
                EntityCandidate(
                    type="breach",
                    value=f"{name} ({rec.source_tag})",
                    attributes=attrs,
                    source_reliability=reliability,
                    confidence=0.7,
                    field_confidence={"in_breach": 0.8, "same_person": 0.7},
                    relation_type="exposed_in",
                    relation_explanation=f"address listed in {name} according to {rec.source_tag}",
                )
            )
            # Identifiers leaked alongside the address are pivot material, but
            # come from dump data: low reliability, moderate identity weight.
            for tag, etype in (("_USERNAME", "username"), ("_NAME", "name"), ("_LASTIP", "ip")):
                for key, values in rec.fields.items():
                    if not key.endswith(tag):
                        continue
                    for value in values:
                        out.append(
                            EntityCandidate(
                                type=etype,
                                value=value,
                                attributes={"origin": f"breach record ({name})", "email": report.email},
                                source_reliability="D",
                                confidence=0.5,
                                field_confidence={"same_person": 0.5},
                                relation_type="breach_associated",
                                relation_explanation=f"{etype} appears with this address in {name}",
                            )
                        )
        return out

    async def health_check(self) -> HealthResult:
        reason = self.configured()
        if reason:
            return HealthResult(False, reason)
        try:
            raws = await self.run(self.health_check_target, [])
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        report: H8mailReport = raws[0].payload
        if report.source_errors:
            return HealthResult(False, f"breach source errors: {report.source_errors[0][:160]}")
        return HealthResult(True, "breach sources reachable")
