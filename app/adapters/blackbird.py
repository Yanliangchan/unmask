"""Blackbird: which sites an email address is registered on (subprocess, GPL-3.0).

Blackbird's email list checks a different set of sites from Holehe (Adobe, Duolingo,
Notion, Spotify, Strava, Chess.com and others), each by the site's own signup or
lookup endpoint. Its username mode uses the WhatsMyName data, which UNMASK already
checks natively (app/adapters/whatsmyname.py), so only the email mode runs here:
counting the same check twice would read as two independent sources.

It is run with ``-v`` so every failed check is printed; a run where most checks
failed is refused instead of reading as "registered nowhere".
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

_FOUND = re.compile(r"✔️?\s+\[(?P<site>[^\]]+)\]\s+(?P<url>\S+)")
_ERROR = re.compile(r"⛔\s+Error in")
_DONE = re.compile(r"Check completed in [\d.]+ seconds \((?P<n>\d+) sites\)")
MAX_ERROR_RATIO = 0.5


@dataclass
class BlackbirdReport:
    email: str
    found: dict[str, str] = field(default_factory=dict)
    errors: int = 0
    sites_checked: int = 0


def parse_output(email: str, stdout: str) -> BlackbirdReport:
    report = BlackbirdReport(email=email)
    done = None
    for line in strip_ansi(stdout).splitlines():
        if m := _DONE.search(line):
            done = int(m["n"])
        if m := _FOUND.search(line):
            report.found[m["site"].strip()] = m["url"]
        elif _ERROR.search(line):
            report.errors += 1
    if done is None:
        raise SignatureMismatch("blackbird did not report completion (run was cut short)")
    report.sites_checked = done
    if done and report.errors / done > MAX_ERROR_RATIO:
        raise SignatureMismatch(f"{report.errors}/{done} checks failed; an empty result would be blindness")
    return report


class BlackbirdAdapter(ToolAdapter):
    name = "blackbird"
    label = "Blackbird"
    input_types = ["email"]
    description = "Checks which of about 15 sites (Adobe, Duolingo, Notion, Spotify, ...) an email address uses."
    health_check_target = "unmask-health@example.com"  # reserved domain: structure only, nobody's address
    timeout_seconds = 180

    def build_argv(self, email: str) -> list[str]:
        email = validate_email(email)
        return [resolve_binary("blackbird"), "-v", "--no-update", "--no-nsfw", "--timeout", "15", "-e", email]

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        email = validate_email(target_value)
        proc = await run_tool_subprocess(self.build_argv(email), timeout=self.timeout_seconds, tool=self.name)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise AdapterError(f"blackbird exited with code {proc.returncode}: {strip_ansi(tail[0])[:300]}")
        return [RawResult(self.name, email, parse_output(email, proc.stdout))]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        r: BlackbirdReport = raw.payload
        return [
            EntityCandidate(
                type="registration",
                value=f"{r.email} @ {site}",
                attributes={"site": site, "email": r.email, "check_url": url},
                source_reliability="B",
                confidence=0.7,
                field_confidence={"registered": 0.8, "same_person": 0.7},
                relation_type="registered_on",
                relation_explanation=f"{site} reports an account registered with this address (Blackbird)",
            )
            for site, url in sorted(r.found.items())
        ]

    async def health_check(self) -> HealthResult:
        try:
            raws = await self.run(self.health_check_target, [])
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        r: BlackbirdReport = raws[0].payload
        return HealthResult(True, f"{r.sites_checked} sites checked, {r.errors} failed")
