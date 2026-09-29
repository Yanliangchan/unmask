"""Sherlock — username presence across ~400 sites (subprocess, MIT)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

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
)

_LINE = re.compile(r"^\[(?P<mark>[+\-])\](?:\s*\[\d+\s*ms\])?\s+(?P<site>[^:]+):\s*(?P<rest>.*)$")
_START = re.compile(r"^\[\*\] Checking username (?P<username>\S+) on:")
_DONE = re.compile(r"^\[\*\] Search completed with (?P<count>\d+) results")
_USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,63}$")

# Above this share of errored/blocked sites the run is not trustworthy: a
# network block or bot wall would otherwise read as "username not found".
MAX_ERROR_RATIO = 0.5
# Sites that must report the health-check username as present.
HEALTH_SIGNATURE_SITES = {"GitHub", "GitLab"}


def validate_username(username: str) -> None:
    """Usernames are passed to CLIs; refuse anything that could parse as a flag."""
    if not _USERNAME.match(username):
        raise InvalidTarget("usernames may only contain letters, digits, '.', '_' and '-'")


@dataclass
class SherlockReport:
    username: str
    found: dict[str, str] = field(default_factory=dict)
    not_found: list[str] = field(default_factory=list)
    errored: dict[str, str] = field(default_factory=dict)
    illegal: list[str] = field(default_factory=list)
    completed_count: int | None = None

    @property
    def checked(self) -> int:
        return len(self.found) + len(self.not_found) + len(self.errored)


def parse_output(stdout: str) -> SherlockReport:
    """Parse ``sherlock --print-all --no-color`` output, validating its signature."""
    lines = [ln.strip() for ln in strip_ansi(stdout).splitlines()]
    report: SherlockReport | None = None
    for line in lines:
        if report is None:
            m = _START.match(line)
            if m:
                report = SherlockReport(username=m["username"])
            continue
        if m := _DONE.match(line):
            report.completed_count = int(m["count"])
            continue
        m = _LINE.match(line)
        if not m:
            continue
        site, rest = m["site"].strip(), m["rest"].strip()
        if m["mark"] == "+":
            report.found[site] = rest
        elif rest.startswith("Not Found!"):
            report.not_found.append(site)
        elif rest.startswith("Illegal Username Format"):
            report.illegal.append(site)
        else:
            report.errored[site] = rest or "unknown error"

    if report is None:
        raise SignatureMismatch("sherlock output is missing its start banner")
    if report.completed_count is None:
        raise SignatureMismatch("sherlock did not report completion (run was cut short)")
    if report.completed_count != len(report.found):
        raise SignatureMismatch(
            f"sherlock reported {report.completed_count} results but {len(report.found)} were parsed"
        )
    if report.checked == 0:
        raise SignatureMismatch("sherlock checked zero sites")
    ratio = len(report.errored) / report.checked
    if ratio > MAX_ERROR_RATIO:
        sample = ", ".join(f"{s} ({r})" for s, r in list(report.errored.items())[:3])
        raise SignatureMismatch(
            f"{len(report.errored)}/{report.checked} sites errored or were blocked — "
            f"results would read as false negatives (e.g. {sample})"
        )
    return report


class SherlockAdapter(ToolAdapter):
    name = "sherlock"
    label = "Sherlock"
    input_types = ["username"]
    description = "Checks whether a username is registered on several hundred sites."
    health_check_target = "torvalds"
    verify_accounts = True

    site_timeout_seconds = 10

    def build_argv(self, username: str, sites: list[str] | None = None) -> list[str]:
        validate_username(username)
        argv = [
            resolve_binary("sherlock"),
            "--print-all",
            "--no-color",
            "--local",  # use the bundled site list; no extra fetch per run
            "--timeout",
            str(self.site_timeout_seconds),
        ]
        for site in sites or []:
            argv += ["--site", site]
        return [*argv, "--", username]

    async def run(self, target_value: str, context_tags: list[str], sites: list[str] | None = None) -> list[RawResult]:
        proc = await run_tool_subprocess(self.build_argv(target_value.strip(), sites))
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise AdapterError(f"sherlock exited with code {proc.returncode}: {tail[0][:300]}")
        report = parse_output(proc.stdout)
        return [RawResult(tool=self.name, target_value=target_value, payload=report)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        report: SherlockReport = raw.payload
        out = []
        for site, url in sorted(report.found.items()):
            out.append(
                EntityCandidate(
                    type="account",
                    value=url,
                    attributes={
                        "site": site,
                        "username": report.username,
                        "url": url,
                        "host": urlparse(url).hostname,
                    },
                    # Presence checks are fairly reliable but prone to false
                    # positives on sites that changed their error pages.
                    source_reliability="C",
                    # Username reuse is weak evidence of the same person.
                    confidence=0.4,
                    field_confidence={"exists": 0.7, "same_person": 0.4},
                    relation_type="has_account",
                    relation_explanation=f"username '{report.username}' registered on {site}",
                )
            )
        return out

    async def health_check(self) -> HealthResult:
        # Only probe the signature sites: fast, and enough to prove the tool
        # can still see a known account.
        try:
            raws = await self.run(self.health_check_target, [], sites=sorted(HEALTH_SIGNATURE_SITES))
            candidates = [c for raw in raws for c in self.parse(raw)]
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        return self.check_health_output(candidates)

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        sites = {c.attributes.get("site") for c in candidates}
        missing = HEALTH_SIGNATURE_SITES - sites
        if missing:
            return HealthResult(False, f"known account not detected on: {', '.join(sorted(missing))}")
        return HealthResult(True, f"{len(candidates)} accounts found for known-good username")
