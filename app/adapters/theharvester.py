"""theHarvester — emails, hosts and IPs for a domain (subprocess, GPL-2.0).

theHarvester prints "No hosts found" and writes a well-formed, empty JSON
report even when every source threw an exception, so the adapter compares the
sources it searched with the exceptions it logged.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from app.adapters.base import (
    AdapterError,
    EntityCandidate,
    HealthResult,
    InvalidTarget,
    RawResult,
    SignatureMismatch,
    ToolAdapter,
    resolve_binary,
    run_tool_subprocess,
    strip_ansi,
    validate_domain,
)
from app.config import get_settings

_SEARCHING = re.compile(r"^\[\*\] Searching (?P<source>\S+?)\.?\s*$")
_EXCEPTION = re.compile(r"^An exception has occurred")
_SOURCE_NAME = re.compile(r"^[a-z0-9_\-]+$")


@dataclass
class HarvesterReport:
    domain: str
    emails: list[str] = field(default_factory=list)
    hosts: dict[str, list[str]] = field(default_factory=dict)  # hostname -> resolved IPs
    ips: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    exceptions: list[str] = field(default_factory=list)


def parse_output(domain: str, stdout: str, report_json: str | None) -> HarvesterReport:
    lines = [ln.strip() for ln in strip_ansi(stdout).splitlines()]
    sources = [m["source"] for ln in lines if (m := _SEARCHING.match(ln))]
    exceptions = [ln[:200] for ln in lines if _EXCEPTION.match(ln)]
    if not report_json:
        raise SignatureMismatch("theHarvester wrote no JSON report (run did not finish)")
    if not sources:
        raise SignatureMismatch("theHarvester searched no sources")
    if len(exceptions) >= len(sources):
        raise SignatureMismatch(
            f"{len(exceptions)} source exception(s) across {len(sources)} source(s) — "
            f"an empty result can't be trusted: {exceptions[0] if exceptions else ''}"
        )
    try:
        data = json.loads(report_json)
    except json.JSONDecodeError as exc:
        raise SignatureMismatch("theHarvester JSON report is malformed") from exc

    report = HarvesterReport(domain=domain, sources=sources, exceptions=exceptions)
    report.emails = sorted({e.strip().lower() for e in data.get("emails", []) if "@" in e})
    for entry in data.get("hosts", []):
        host, _, ips = str(entry).partition(":")
        host = host.strip().lower().rstrip(".")
        if not host:
            continue
        resolved = report.hosts.setdefault(host, [])
        resolved.extend(ip.strip() for ip in ips.split(",") if ip.strip() and ip.strip() not in resolved)
    report.ips = sorted(set(data.get("ips", [])))
    report.urls = sorted(set(data.get("interesting_urls", [])))
    return report


class TheHarvesterAdapter(ToolAdapter):
    name = "theharvester"
    label = "theHarvester"
    input_types = ["domain"]
    description = "Collects emails, subdomains and IPs for a domain from public sources."
    health_check_target = "example.com"
    timeout_seconds = 600

    def sources(self) -> str:
        names = [s.strip() for s in get_settings().harvester_sources.split(",")]
        names = [s for s in names if _SOURCE_NAME.match(s)]
        if not names:
            raise InvalidTarget("UNMASK_HARVESTER_SOURCES lists no valid sources")
        return ",".join(names)

    def build_argv(self, domain: str, sources: str | None = None) -> list[str]:
        domain = validate_domain(domain)
        return [resolve_binary("theHarvester"), "-d", domain, "-b", sources or self.sources(), "-f", "report"]

    async def run(self, target_value: str, context_tags: list[str], sources: str | None = None) -> list[RawResult]:
        domain = validate_domain(target_value)
        proc = await run_tool_subprocess(
            self.build_argv(domain, sources), timeout=self.timeout_seconds, collect=["report.json"]
        )
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise AdapterError(f"theHarvester exited with code {proc.returncode}: {strip_ansi(tail[0])[:300]}")
        report = parse_output(domain, proc.stdout + "\n" + proc.stderr, proc.files.get("report.json"))
        return [RawResult(tool=self.name, target_value=domain, payload=report)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        r: HarvesterReport = raw.payload
        out = []
        for email in r.emails:
            out.append(
                EntityCandidate(
                    type="email",
                    value=email,
                    attributes={"domain": r.domain, "sources": r.sources},
                    source_reliability="C",
                    # Belongs to the organisation; says little about one person.
                    confidence=0.5,
                    field_confidence={"belongs_to_domain": 0.8, "same_person": 0.3},
                    relation_type="email_at_domain",
                    relation_explanation=f"address published under {r.domain} (theHarvester)",
                )
            )
        for host, ips in sorted(r.hosts.items()):
            out.append(
                EntityCandidate(
                    type="hostname",
                    value=host,
                    attributes={"domain": r.domain, "resolved_ips": ips},
                    source_reliability="C",
                    confidence=0.6,
                    field_confidence={"belongs_to_domain": 0.8},
                    relation_type="subdomain",
                    relation_explanation=f"host observed under {r.domain} (theHarvester)",
                )
            )
        for ip in r.ips:
            out.append(
                EntityCandidate(
                    type="ip",
                    value=ip,
                    attributes={"domain": r.domain},
                    source_reliability="C",
                    confidence=0.5,
                    field_confidence={"belongs_to_domain": 0.6},
                    relation_type="resolves_to",
                    relation_explanation=f"address associated with {r.domain} (theHarvester)",
                )
            )
        return out

    async def health_check(self) -> HealthResult:
        try:
            raws = await self.run(self.health_check_target, [], sources="crtsh")
            candidates = [c for raw in raws for c in self.parse(raw)]
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        if not any(c.type == "hostname" for c in candidates):
            return HealthResult(False, "no hosts found for a domain with public certificates")
        return HealthResult(True, f"{len(candidates)} results for known-good domain")
