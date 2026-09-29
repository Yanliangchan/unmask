"""OWASP Amass — passive subdomain enumeration (subprocess, Apache-2.0).

Pinned to Amass v3.23.x, whose ``-json`` output is one JSON object per
discovered name. Passive mode only: no brute forcing or active probing of the
target's infrastructure.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from app.adapters.base import (
    AdapterError,
    EntityCandidate,
    RawResult,
    SignatureMismatch,
    ToolAdapter,
    resolve_binary,
    run_tool_subprocess,
    strip_ansi,
    validate_domain,
)

_QUERYING = re.compile(r"Querying (?P<source>\S+) for \S+ subdomains")
_LOG_LINE = re.compile(r"^(?:[\d:.]+\s+)?(?P<source>[A-Za-z0-9]+): (?P<msg>.+)$")
# API-keyed sources without a key log this at startup; not a failure.
_UNCONFIGURED = "check callback failed for the configuration"
MINUTES = 8
MAX_ERROR_RATIO = 0.5


@dataclass
class AmassReport:
    domain: str
    names: dict[str, dict] = field(default_factory=dict)
    sources_queried: list[str] = field(default_factory=list)
    source_errors: dict[str, str] = field(default_factory=dict)


def parse_output(domain: str, json_lines: str | None, output: str, log: str | None) -> AmassReport:
    if "The enumeration has finished" not in strip_ansi(output):
        raise SignatureMismatch("amass did not report completion (run was cut short)")
    report = AmassReport(domain=domain)
    log_lines = (log or "").splitlines()
    queried = sorted({m["source"] for ln in log_lines if (m := _QUERYING.search(ln))})
    report.sources_queried = queried
    for ln in log_lines:
        m = _LOG_LINE.match(ln.strip())
        if m and m["source"] in queried and _UNCONFIGURED not in m["msg"]:
            report.source_errors.setdefault(m["source"], m["msg"][:200])
    if not queried:
        raise SignatureMismatch("amass queried no data sources")
    if len(report.source_errors) / len(queried) > MAX_ERROR_RATIO:
        sample = ", ".join(f"{s} ({e[:50]})" for s, e in list(report.source_errors.items())[:3])
        raise SignatureMismatch(
            f"{len(report.source_errors)}/{len(queried)} data sources failed — "
            f"results would read as false negatives (e.g. {sample})"
        )
    for line in (json_lines or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError as exc:
            raise SignatureMismatch("amass JSON output is malformed") from exc
        name = str(rec.get("name", "")).lower().rstrip(".")
        if not name or (name != domain and not name.endswith("." + domain)):
            continue
        entry = report.names.setdefault(name, {"addresses": [], "sources": [], "tag": rec.get("tag")})
        for addr in rec.get("addresses") or []:
            ip = addr.get("ip")
            if ip and ip not in [a["ip"] for a in entry["addresses"]]:
                entry["addresses"].append(
                    {"ip": ip, "cidr": addr.get("cidr"), "asn": addr.get("asn"), "desc": addr.get("desc")}
                )
        entry["sources"] = sorted(set(entry["sources"]) | set(rec.get("sources") or []))
    return report


class AmassAdapter(ToolAdapter):
    name = "amass"
    label = "Amass"
    speed = "slow"
    input_types = ["domain"]
    description = "Passive subdomain enumeration from dozens of public data sources."
    health_check_target = "example.com"
    timeout_seconds = (MINUTES + 3) * 60

    def build_argv(self, domain: str) -> list[str]:
        domain = validate_domain(domain)
        return [
            resolve_binary("amass"),
            "enum",
            "-passive",
            "-nocolor",
            "-timeout",
            str(MINUTES),
            "-dir",
            "amass-data",
            "-json",
            "names.json",
            "-log",
            "amass.log",
            "-d",
            domain,
        ]

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        proc = await run_tool_subprocess(
            self.build_argv(domain), timeout=self.timeout_seconds, collect=["names.json", "amass.log"], tool=self.name
        )
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise AdapterError(f"amass exited with code {proc.returncode}: {strip_ansi(tail[0])[:300]}")
        report = parse_output(
            domain, proc.files.get("names.json"), proc.stdout + "\n" + proc.stderr, proc.files.get("amass.log")
        )
        return [RawResult(tool=self.name, target_value=domain, payload=report)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        r: AmassReport = raw.payload
        return [
            EntityCandidate(
                type="hostname",
                value=name,
                attributes={"domain": r.domain, **info},
                source_reliability="C",
                confidence=0.6,
                field_confidence={"belongs_to_domain": 0.8},
                relation_type="subdomain",
                relation_explanation=f"found by Amass via {', '.join(info['sources']) or 'passive sources'}",
            )
            for name, info in sorted(r.names.items())
            if name != r.domain
        ]
