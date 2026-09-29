"""SpiderFoot — broad automated OSINT for domains and IPs (CLI mode, MIT).

SpiderFoot's CLI exits 0 and prints ``[]`` even when the scan itself failed;
the only reliable signal is its "Scan completed with status ..." log line.
"""

from __future__ import annotations

import ipaddress
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

_STATUS = re.compile(r"Scan completed with status (?P<status>[A-Z\-]+)")
_MODULE_ERROR = re.compile(r"\[ERROR\] (?P<module>sfp_\w+)")
USE_CASES = {"passive", "footprint", "investigate", "all"}

# SpiderFoot's JSON uses event-type descriptions. Only identity-bearing types
# become entities; the rest stay out of the case to keep it reviewable.
TYPE_MAP = {
    "Internet Name": ("hostname", "C", 0.6),
    "Affiliate - Internet Name": ("hostname", "D", 0.3),
    "Domain Name": ("domain", "C", 0.6),
    "Email Address": ("email", "C", 0.5),
    "IP Address": ("ip", "C", 0.5),
    "IPv6 Address": ("ip", "C", 0.5),
    "Human Name": ("name", "D", 0.3),
    "Username": ("username", "D", 0.4),
    "Phone Number": ("phone", "C", 0.4),
    "Account on External Site": ("account", "C", 0.4),
    "Social Media Presence": ("account", "C", 0.4),
    "Hacked Email Address": ("breach", "C", 0.5),
}


@dataclass
class SpiderFootReport:
    target: str
    events: list[dict] = field(default_factory=list)
    module_errors: list[str] = field(default_factory=list)


def parse_output(target: str, stdout: str, stderr: str) -> SpiderFootReport:
    log = strip_ansi(stderr + "\n" + stdout)
    statuses = _STATUS.findall(log)
    if not statuses:
        raise SignatureMismatch("SpiderFoot did not report a final scan status (run was cut short)")
    if statuses[-1] != "FINISHED":
        raise SignatureMismatch(f"SpiderFoot scan ended with status {statuses[-1]}")
    start, end = stdout.find("["), stdout.rfind("]")
    if start == -1 or end < start:
        raise SignatureMismatch("SpiderFoot printed no JSON results")
    try:
        events = json.loads(stdout[start : end + 1])
    except json.JSONDecodeError as exc:
        raise SignatureMismatch("SpiderFoot JSON output is malformed") from exc
    if not isinstance(events, list):
        raise SignatureMismatch("SpiderFoot JSON output is not a list")
    errors = sorted(set(_MODULE_ERROR.findall(log)))
    return SpiderFootReport(target=target, events=[e for e in events if isinstance(e, dict)], module_errors=errors)


class SpiderFootAdapter(ToolAdapter):
    name = "spiderfoot"
    label = "SpiderFoot"
    speed = "slow"
    input_types = ["domain", "ip"]
    description = "Runs SpiderFoot's module set (passive by default) against a domain or IP."
    health_check_target = "example.com"
    timeout_seconds = 45 * 60

    def validate(self, value: str) -> str:
        value = value.strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return validate_domain(value)

    def build_argv(self, target: str, modules: list[str] | None = None) -> list[str]:
        target = self.validate(target)
        argv = [resolve_binary("spiderfoot"), "-s", target, "-o", "json", "-max-threads", "3"]
        if modules:
            argv += ["-m", ",".join(modules)]
        else:
            use_case = get_settings().spiderfoot_use_case
            if use_case not in USE_CASES:
                raise InvalidTarget(f"UNMASK_SPIDERFOOT_USE_CASE must be one of {sorted(USE_CASES)}")
            argv += ["-u", use_case]
        return argv

    async def run(
        self, target_value: str, context_tags: list[str], modules: list[str] | None = None
    ) -> list[RawResult]:
        target = self.validate(target_value)
        proc = await run_tool_subprocess(self.build_argv(target, modules), timeout=self.timeout_seconds, tool=self.name)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise AdapterError(f"spiderfoot exited with code {proc.returncode}: {strip_ansi(tail[0])[:300]}")
        report = parse_output(target, proc.stdout, proc.stderr)
        return [RawResult(tool=self.name, target_value=target, payload=report)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        r: SpiderFootReport = raw.payload
        seen: dict[tuple[str, str], EntityCandidate] = {}
        for ev in r.events:
            mapped = TYPE_MAP.get(str(ev.get("type")))
            data = str(ev.get("data", "")).strip()
            if not mapped or not data or len(data) > 512:
                continue
            etype, reliability, confidence = mapped
            if etype in ("hostname", "domain", "email"):
                data = data.lower()
            if (etype, data) == ("domain", r.target) or (etype, data) == ("ip", r.target):
                continue
            key = (etype, data)
            cand = seen.get(key)
            module = str(ev.get("module", ""))
            if cand is None:
                seen[key] = EntityCandidate(
                    type=etype,
                    value=data,
                    attributes={"target": r.target, "sf_type": ev.get("type"), "modules": [module]},
                    source_reliability=reliability,
                    confidence=confidence,
                    field_confidence={"related_to_target": confidence},
                    relation_type="spiderfoot_link",
                    relation_explanation=f"{ev.get('type')} reported by {module} (SpiderFoot)",
                )
            elif module not in cand.attributes["modules"]:
                cand.attributes["modules"].append(module)
        if r.module_errors:
            for cand in seen.values():
                cand.attributes["module_errors"] = r.module_errors
        return list(seen.values())

    async def health_check(self) -> HealthResult:
        try:
            raws = await self.run(self.health_check_target, [], modules=["sfp_dnsresolve"])
        except AdapterError as exc:
            return HealthResult(False, str(exc))
        return HealthResult(True, f"scan finished with {len(raws[0].payload.events)} events")
