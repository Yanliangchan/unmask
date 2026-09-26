"""crt.sh — certificate transparency search for a domain (HTTP API)."""

from __future__ import annotations

from app.adapters import http
from app.adapters.base import (
    EntityCandidate,
    HealthResult,
    RawResult,
    SignatureMismatch,
    ToolAdapter,
    validate_domain,
)
from app.config import get_settings


def hostnames_from(rows: list[dict], domain: str) -> dict[str, dict]:
    """Collapse certificate rows into hostnames under ``domain``."""
    hosts: dict[str, dict] = {}
    for row in rows:
        names = str(row.get("name_value", "")).splitlines() + [str(row.get("common_name", ""))]
        for name in names:
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if not name or " " in name or "@" in name:
                continue
            if name != domain and not name.endswith("." + domain):
                continue
            entry = hosts.setdefault(name, {"certificates": 0, "first_cert": None, "last_cert": None, "issuers": set()})
            entry["certificates"] += 1
            nb, na = row.get("not_before"), row.get("not_after")
            if nb and (entry["first_cert"] is None or nb < entry["first_cert"]):
                entry["first_cert"] = nb
            if na and (entry["last_cert"] is None or na > entry["last_cert"]):
                entry["last_cert"] = na
            if row.get("issuer_name"):
                entry["issuers"].add(str(row["issuer_name"])[:200])
    for entry in hosts.values():
        entry["issuers"] = sorted(entry["issuers"])[:5]
    return hosts


class CrtShAdapter(ToolAdapter):
    name = "crtsh"
    label = "crt.sh"
    input_types = ["domain"]
    description = "Certificate-transparency logs: every hostname that has had a public TLS certificate."
    health_check_target = "example.com"
    timeout_seconds = 120

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        _, data = await http.get_json(
            get_settings().crtsh_url,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=self.timeout_seconds,
        )
        if not isinstance(data, list) or any(not isinstance(r, dict) for r in data):
            raise SignatureMismatch("crt.sh returned JSON that is not a list of certificates")
        return [RawResult(tool=self.name, target_value=domain, payload={"domain": domain, "rows": data})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        domain = raw.payload["domain"]
        return [
            EntityCandidate(
                type="hostname",
                value=host,
                attributes={"domain": domain, **info},
                # CT logs are authoritative that a certificate was issued.
                source_reliability="B",
                confidence=0.6,
                field_confidence={"belongs_to_domain": 0.9},
                relation_type="subdomain",
                relation_explanation=f"{info['certificates']} certificate(s) name this host (crt.sh)",
            )
            for host, info in sorted(hostnames_from(raw.payload["rows"], domain).items())
            if host != domain
        ]

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        if candidates:
            return HealthResult(True, f"{len(candidates)} hostnames for known-good domain")
        return HealthResult(False, "no certificates found for a domain known to have them")
