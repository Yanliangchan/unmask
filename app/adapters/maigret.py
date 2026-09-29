"""Maigret — username dossier across thousands of sites (subprocess, MIT)."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

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
)
from app.adapters.sherlock import validate_username
from app.adapters.sites import focused_sites
from app.config import get_settings

_START = re.compile(r"^\[\*\] Checking username (?P<username>\S+) on:")
_SITES = re.compile(r"Starting a search on top (?P<n>\d+) sites")
_FOUND = re.compile(r"^\[\+\] (?P<site>[^:]+?)(?: \[[^\]]+\])?: (?P<url>\S+)")
_ERROR = re.compile(r"^\[\?\] (?P<site>[^:]+?)(?: \[[^\]]+\])?: (?P<reason>.*)$")
_DONE = re.compile(r"returned (?P<count>\d+) accounts?")

MAX_ERROR_RATIO = 0.5
# Extracted profile fields worth keeping; everything else stays in raw output.
_ID_FIELDS = {"fullname", "name", "bio", "location", "country", "city", "website", "links", "image", "created_at"}


@dataclass
class MaigretReport:
    username: str
    sites_checked: int
    found: dict[str, str] = field(default_factory=dict)
    errored: dict[str, str] = field(default_factory=dict)
    records: list[dict] = field(default_factory=list)


def parse_output(stdout: str, ndjson: str) -> MaigretReport:
    lines = [ln.strip() for ln in strip_ansi(stdout).splitlines()]
    username, sites, done = None, None, None
    found: dict[str, str] = {}
    errored: dict[str, str] = {}
    for line in lines:
        if m := _START.match(line):
            username = m["username"]
        elif m := _SITES.search(line):
            sites = int(m["n"])
        elif m := _FOUND.match(line):
            found[m["site"].strip()] = m["url"]
        elif m := _ERROR.match(line):
            errored[m["site"].strip()] = m["reason"].strip()[:200]
        elif m := _DONE.search(line):
            done = int(m["count"])
    if username is None or sites is None:
        raise SignatureMismatch("maigret output is missing its start banner")
    if done is None:
        raise SignatureMismatch("maigret did not report completion (run was cut short)")
    if sites == 0:
        raise SignatureMismatch("maigret checked zero sites")
    if len(errored) / sites > MAX_ERROR_RATIO:
        sample = ", ".join(f"{s} ({r[:40]})" for s, r in list(errored.items())[:3])
        raise SignatureMismatch(
            f"{len(errored)}/{sites} sites errored or were blocked — "
            f"results would read as false negatives (e.g. {sample})"
        )
    records = []
    for line in ndjson.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise SignatureMismatch("maigret report is not valid ndjson") from exc
    if len(records) != done:
        raise SignatureMismatch(f"maigret reported {done} accounts but its report holds {len(records)}")
    return MaigretReport(username=username, sites_checked=sites, found=found, errored=errored, records=records)


class MaigretAdapter(ToolAdapter):
    name = "maigret"
    label = "Maigret"
    input_types = ["username"]
    description = "Username search across thousands of sites, extracting profile details where public."
    health_check_target = "torvalds"
    timeout_seconds = 900
    verify_accounts = True

    site_timeout_seconds = 10

    def build_argv(self, username: str, sites: list[str] | None = None) -> list[str]:
        validate_username(username)
        argv = [
            resolve_binary("maigret"),
            "--no-color",
            "--no-progressbar",
            "--print-errors",
            # Pivoting is the platform's job, where it is logged; not the tool's.
            "--no-recursion",
            "--timeout",
            str(self.site_timeout_seconds),
            "-J",
            "ndjson",
            "-fo",
            "out",
        ]
        if sites:
            for site in sites:
                argv += ["--site", site]
        else:
            argv += ["--top-sites", str(get_settings().maigret_top_sites)]
        return [*argv, "--", username]

    async def run(self, target_value: str, context_tags: list[str], sites: list[str] | None = None) -> list[RawResult]:
        username = target_value.strip()
        sites = sites or focused_sites(self.name)
        proc = await run_tool_subprocess(
            self.build_argv(username, sites), timeout=self.timeout_seconds, collect=["out/*ndjson*.json"]
        )
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise AdapterError(f"maigret exited with code {proc.returncode}: {strip_ansi(tail[0])[:300]}")
        ndjson = "\n".join(proc.files.values())
        report = parse_output(proc.stdout + "\n" + proc.stderr, ndjson)
        return [RawResult(tool=self.name, target_value=username, payload=report)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        report: MaigretReport = raw.payload
        out = []
        for rec in report.records:
            status = rec.get("status") or {}
            url = status.get("url") or rec.get("url_user")
            if not url:
                continue
            site = rec.get("sitename") or status.get("site_name") or urlparse(url).hostname
            ids = {k: v for k, v in (status.get("ids") or {}).items() if k in _ID_FIELDS}
            field_conf = {"exists": 0.75, "same_person": 0.4}
            if ids:
                # A profile exposing its own details is a little stronger evidence.
                field_conf["profile_fields"] = 0.6
            out.append(
                EntityCandidate(
                    type="account",
                    value=url,
                    attributes={
                        "site": site,
                        "username": report.username,
                        "url": url,
                        "host": urlparse(url).hostname,
                        "tags": status.get("tags") or [],
                        "profile": ids,
                    },
                    source_reliability="C",
                    confidence=0.45 if ids else 0.4,
                    field_confidence=field_conf,
                    relation_type="has_account",
                    relation_explanation=f"username '{report.username}' found on {site} by Maigret",
                )
            )
        return out

    async def health_check(self) -> HealthResult:
        try:
            raws = await self.run(self.health_check_target, [], sites=["GitHub"])
            candidates = [c for raw in raws for c in self.parse(raw)]
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        if not any((c.attributes.get("host") or "").endswith("github.com") for c in candidates):
            return HealthResult(False, "known GitHub account not detected")
        return HealthResult(True, "known-good username found on GitHub")
