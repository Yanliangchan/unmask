"""Holehe — which sites an email address is registered on (subprocess, GPL-3.0).

Holehe is always run with ``--no-password-recovery``: the recovery-based
checks send password-reset flows that can notify the subject.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

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

_LINE = re.compile(r"^\[(?P<mark>[+\-x])\] (?P<site>\S+)(?: / (?P<extra>.*))?$")
_DONE = re.compile(r"^(?P<n>\d+) websites checked in")

MAX_RATE_LIMITED_RATIO = 0.5
MIN_SITES = 20


@dataclass
class HoleheReport:
    email: str
    used: dict[str, str] = field(default_factory=dict)
    not_used: list[str] = field(default_factory=list)
    rate_limited: list[str] = field(default_factory=list)
    sites_checked: int = 0


def parse_output(email: str, stdout: str) -> HoleheReport:
    report = HoleheReport(email=email)
    done = None
    for raw in strip_ansi(stdout).splitlines():
        line = raw.strip()
        if m := _DONE.match(line):
            done = int(m["n"])
        elif m := _LINE.match(line):
            site = m["site"]
            if m["mark"] == "+":
                report.used[site] = (m["extra"] or "").strip()
            elif m["mark"] == "-":
                report.not_used.append(site)
            else:
                report.rate_limited.append(site)
    if done is None:
        raise SignatureMismatch("holehe did not report completion (run was cut short)")
    report.sites_checked = done
    classified = len(report.used) + len(report.not_used) + len(report.rate_limited)
    if classified < min(done, MIN_SITES):
        raise SignatureMismatch(f"holehe reported {done} sites checked but only {classified} results were printed")
    if done and len(report.rate_limited) / done > MAX_RATE_LIMITED_RATIO:
        raise SignatureMismatch(
            f"{len(report.rate_limited)}/{done} sites rate-limited or errored — results would read as false negatives"
        )
    return report


class HoleheAdapter(ToolAdapter):
    name = "holehe"
    label = "Holehe"
    input_types = ["email"]
    description = "Checks which sites an email address is registered on (password-recovery checks disabled)."
    # Reserved domain: registered nowhere, so the check validates structure only
    # and never probes a real person's address.
    health_check_target = "unmask-health@example.com"
    timeout_seconds = 300

    def configured(self) -> str | None:
        from app.config import get_settings
        from app.proxy import proxy_for

        if proxy_for(self.name) or get_settings().holehe_direct:
            return None
        return (
            "needs a proxy: the sites Holehe checks block requests from cloud servers, so it would only report "
            "false negatives. Set UNMASK_PROXY_URL (or UNMASK_HOLEHE_DIRECT=true on a home or office network)"
        )

    def build_argv(self, email: str) -> list[str]:
        email = validate_email(email)
        return [
            resolve_binary("holehe"),
            "--no-color",
            "--no-clear",
            "--no-password-recovery",
            "-T",
            "15",
            "--",
            email,
        ]

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        email = validate_email(target_value)
        proc = await run_tool_subprocess(self.build_argv(email), timeout=self.timeout_seconds, tool=self.name)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise AdapterError(f"holehe exited with code {proc.returncode}: {strip_ansi(tail[0])[:300]}")
        return [RawResult(tool=self.name, target_value=email, payload=parse_output(email, proc.stdout))]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        report: HoleheReport = raw.payload
        return [
            EntityCandidate(
                type="registration",
                value=f"{report.email} @ {site}",
                attributes={"site": site, "email": report.email, "detail": extra or None},
                # Direct check against the site's own signup/login flow.
                source_reliability="B",
                # Tied to the exact address, so strong for "this address's owner".
                confidence=0.7,
                field_confidence={"registered": 0.8, "same_person": 0.7},
                relation_type="registered_on",
                relation_explanation=f"{site} reports an account registered with this address",
            )
            for site, extra in sorted(report.used.items())
        ]

    async def health_check(self) -> HealthResult:
        try:
            raws = await self.run(self.health_check_target, [])
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        report: HoleheReport = raws[0].payload
        return HealthResult(
            True,
            f"{report.sites_checked} sites checked, {len(report.rate_limited)} rate-limited",
        )
