"""Lookups that need an API key, entered on the Integrations page (or set in the environment).

Each adapter reports "not configured" until its key is present, so it is never
offered, run, or counted as "nothing found" without one. Health checks use
free account endpoints where the service has one, so testing a key doesn't
spend lookup credits.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote

from app.adapters.base import (
    AdapterError,
    EntityCandidate,
    HealthResult,
    InvalidTarget,
    RawResult,
    SignatureMismatch,
    ToolAdapter,
    validate_domain,
    validate_email,
)
from app.adapters.lookups import enrich, fetch_json
from app.config import get_settings


def _missing(setting: str, label: str) -> str | None:
    if getattr(get_settings(), setting, ""):
        return None
    return f"needs an API key ({label}): add it on the Integrations page"


def validate_ip(value: str) -> str:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        raise InvalidTarget(f"'{value}' is not an IP address") from None
    if not ip.is_global:
        raise InvalidTarget(f"'{value}' is not a public IP address")
    return str(ip)


def validate_phone(value: str) -> str:
    digits = re.sub(r"[^\d+]", "", value)
    digits = digits[1:] if digits.startswith("+") else digits
    if not digits.isdigit() or not 7 <= len(digits) <= 15:
        raise InvalidTarget(f"'{value}' is not a phone number in international format")
    return digits


async def _account_ok(url: str, **kw) -> HealthResult:
    try:
        data = await fetch_json(url, **kw)
    except AdapterError as exc:
        return HealthResult(False, str(exc))
    return HealthResult(
        data is not None, "the key works" if data is not None else "the service didn't recognise the key"
    )


# --- Have I Been Pwned ---------------------------------------------------------------------------


class HibpAdapter(ToolAdapter):
    name = "hibp"
    label = "Have I Been Pwned"
    input_types = ["email"]
    description = "Which verified data breaches an email address appears in, and what each one exposed."
    health_check_target = "account-exists@hibp-integration-tests.com"
    timeout_seconds = 30

    def configured(self) -> str | None:
        return _missing("hibp_key", "Have I Been Pwned")

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        email = validate_email(target_value)
        data = await fetch_json(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}",
            params={"truncateResponse": "false"},
            headers={"hibp-api-key": get_settings().hibp_key, "user-agent": "unmask-osint"},
        )
        if data is not None and not isinstance(data, list):
            raise SignatureMismatch("Have I Been Pwned returned an unexpected breach list")
        return [RawResult(self.name, email, {"email": email, "breaches": data or []})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        return [
            EntityCandidate(
                type="breach",
                value=f"{b.get('Title') or b.get('Name')} (HIBP)",
                attributes={
                    "breach": b.get("Name"),
                    "domain": b.get("Domain"),
                    "date": b.get("BreachDate"),
                    "fields": b.get("DataClasses") or [],
                    "verified_breach": b.get("IsVerified"),
                    "source": "hibp",
                    "email": raw.payload["email"],
                },
                source_reliability="A" if b.get("IsVerified") else "B",
                confidence=0.75,
                field_confidence={"in_breach": 0.9, "same_person": 0.75},
                relation_type="exposed_in",
                relation_explanation=f"address listed in the {b.get('Title') or b.get('Name')} breach (HIBP)",
            )
            for b in raw.payload["breaches"]
        ]


# --- Hunter --------------------------------------------------------------------------------------


class HunterAdapter(ToolAdapter):
    name = "hunter"
    label = "Hunter"
    input_types = ["domain"]
    description = "Email addresses published for people at a domain, with their names and roles."
    timeout_seconds = 30

    def configured(self) -> str | None:
        return _missing("hunter_key", "Hunter")

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        data = await fetch_json(
            "https://api.hunter.io/v2/domain-search",
            params={"domain": domain, "limit": 50, "api_key": get_settings().hunter_key},
        )
        if not isinstance(data, dict) or "data" not in data:
            raise SignatureMismatch("Hunter returned an unexpected response")
        return [RawResult(self.name, domain, {"domain": domain, "data": data["data"] or {}})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        out = []
        for e in raw.payload["data"].get("emails") or []:
            value = (e.get("value") or "").lower()
            if not value:
                continue
            person = " ".join(x for x in (e.get("first_name"), e.get("last_name")) if x)
            out.append(
                EntityCandidate(
                    "email",
                    value,
                    {
                        "origin": "Hunter",
                        "name": person or None,
                        "position": e.get("position"),
                        "department": e.get("department"),
                        "hunter_confidence": e.get("confidence"),
                        "sources": [s.get("uri") for s in e.get("sources") or []][:5],
                        "linkedin": e.get("linkedin"),
                        "twitter": e.get("twitter"),
                    },
                    "C",
                    0.45,
                    {"belongs_to_domain": 0.8, "same_person": 0.3},
                    "email_at_domain",
                    f"published address at {raw.payload['domain']} ({e.get('confidence', '?')}% per Hunter)",
                )
            )
        return out

    async def health_check(self) -> HealthResult:
        return await _account_ok("https://api.hunter.io/v2/account", params={"api_key": get_settings().hunter_key})


# --- EmailRep ------------------------------------------------------------------------------------


class EmailRepAdapter(ToolAdapter):
    name = "emailrep"
    label = "EmailRep"
    input_types = ["email"]
    description = (
        "An address's reputation: age, whether it's disposable or deliverable, and which sites it has profiles on."
    )
    health_check_target = "bill@microsoft.com"
    timeout_seconds = 30

    def configured(self) -> str | None:
        return _missing("emailrep_key", "EmailRep")

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        email = validate_email(target_value)
        data = await fetch_json(
            f"https://emailrep.io/{quote(email)}",
            headers={"Key": get_settings().emailrep_key, "User-Agent": "unmask-osint"},
        )
        if not isinstance(data, dict) or "reputation" not in data:
            raise SignatureMismatch("EmailRep returned an unexpected response")
        return [RawResult(self.name, email, data)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        d = raw.payload
        details = d.get("details") or {}
        email = raw.target_value
        attrs = {
            "reputation": d.get("reputation"),
            "suspicious": d.get("suspicious"),
            "references": d.get("references"),
            "first_seen": details.get("first_seen"),
            "last_seen": details.get("last_seen"),
            "deliverable": details.get("deliverable"),
            "disposable": details.get("disposable"),
            "free_provider": details.get("free_provider"),
            "in_breaches": details.get("data_breach"),
        }
        out = [enrich("email", email, "emailrep", attrs)]
        for site in details.get("profiles") or []:
            out.append(
                EntityCandidate(
                    "registration",
                    f"{email} @ {site}",
                    {"site": site, "email": email, "origin": "EmailRep"},
                    "C",
                    0.6,
                    {"registered": 0.7, "same_person": 0.6},
                    "registered_on",
                    f"EmailRep lists a {site} profile for this address",
                )
            )
        return out


# --- Shodan / IPinfo -----------------------------------------------------------------------------


class ShodanAdapter(ToolAdapter):
    name = "shodan"
    label = "Shodan"
    input_types = ["ip"]
    description = "Open ports, running services and hostnames Shodan has seen on an IP address."
    timeout_seconds = 30

    def configured(self) -> str | None:
        return _missing("shodan_key", "Shodan")

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        ip = validate_ip(target_value)
        data = await fetch_json(
            f"https://api.shodan.io/shodan/host/{ip}", params={"key": get_settings().shodan_key, "minify": "true"}
        )
        return [RawResult(self.name, ip, {"ip": ip, "host": data or {}})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        h, ip = raw.payload["host"], raw.payload["ip"]
        if not h:
            return []
        attrs = {
            "ports": h.get("ports"),
            "org": h.get("org"),
            "isp": h.get("isp"),
            "asn": h.get("asn"),
            "os": h.get("os"),
            "country": h.get("country_name"),
            "city": h.get("city"),
            "last_update": h.get("last_update"),
        }
        out = [enrich("ip", ip, "shodan", attrs)]
        for name in (h.get("hostnames") or [])[:20]:
            out.append(
                EntityCandidate(
                    "hostname",
                    name.lower(),
                    {"origin": "Shodan", "ip": ip},
                    "B",
                    0.6,
                    {"resolves_to": 0.8},
                    "resolves_to",
                    f"Shodan sees {name} on {ip}",
                )
            )
        return out

    async def health_check(self) -> HealthResult:
        return await _account_ok("https://api.shodan.io/api-info", params={"key": get_settings().shodan_key})


class IpinfoAdapter(ToolAdapter):
    name = "ipinfo"
    label = "IPinfo"
    input_types = ["ip"]
    description = "Where an IP address is, who operates its network, and its hostname."
    health_check_target = "8.8.8.8"
    timeout_seconds = 30

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        ip = validate_ip(target_value)
        token = get_settings().ipinfo_token
        data = await fetch_json(f"https://ipinfo.io/{ip}/json", params={"token": token} if token else None)
        if not isinstance(data, dict):
            raise SignatureMismatch("IPinfo returned an unexpected response")
        return [RawResult(self.name, ip, data)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        d = raw.payload
        attrs = {k: d.get(k) for k in ("hostname", "city", "region", "country", "org", "loc", "timezone") if d.get(k)}
        out = [enrich("ip", raw.target_value, "ipinfo", attrs)]
        if d.get("hostname"):
            out.append(
                EntityCandidate(
                    "hostname",
                    d["hostname"].lower(),
                    {"origin": "IPinfo reverse DNS"},
                    "B",
                    0.6,
                    {"resolves_to": 0.8},
                    "reverse_dns",
                    f"reverse DNS of {raw.target_value}",
                )
            )
        return out

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        ok = bool(candidates) and "Google" in str(candidates[0].attributes.get("ipinfo", {}).get("org", ""))
        return HealthResult(ok, "known address returned its network owner" if ok else "known address returned nothing")


# --- VirusTotal / SecurityTrails -----------------------------------------------------------------


def _hostnames(names: list[str], domain: str, tool: str) -> list[EntityCandidate]:
    seen, out = set(), []
    for n in names:
        n = (n or "").lower().rstrip(".")
        if n and n != domain and n.endswith("." + domain) and n not in seen:
            seen.add(n)
            out.append(
                EntityCandidate(
                    "hostname",
                    n,
                    {"domain": domain, "origin": tool},
                    "B",
                    0.6,
                    {"belongs_to_domain": 0.9},
                    "subdomain",
                    f"subdomain of {domain} ({tool})",
                )
            )
    return out


class VirusTotalAdapter(ToolAdapter):
    name = "virustotal"
    label = "VirusTotal"
    input_types = ["domain"]
    description = "A domain's subdomains and the IP addresses it has resolved to (passive DNS)."
    health_check_target = "example.com"
    timeout_seconds = 60

    def configured(self) -> str | None:
        return _missing("virustotal_key", "VirusTotal")

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        headers = {"x-apikey": get_settings().virustotal_key}
        subs = await fetch_json(
            f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains", params={"limit": 40}, headers=headers
        )
        res = await fetch_json(
            f"https://www.virustotal.com/api/v3/domains/{domain}/resolutions", params={"limit": 20}, headers=headers
        )
        return [
            RawResult(
                self.name,
                domain,
                {
                    "domain": domain,
                    "subdomains": (subs or {}).get("data") or [],
                    "resolutions": (res or {}).get("data") or [],
                },
            )
        ]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        domain = raw.payload["domain"]
        out = _hostnames([s.get("id", "") for s in raw.payload["subdomains"]], domain, "VirusTotal")
        seen = set()
        for r in raw.payload["resolutions"]:
            a = r.get("attributes") or {}
            ip = a.get("ip_address")
            if ip and ip not in seen:
                seen.add(ip)
                out.append(
                    EntityCandidate(
                        "ip",
                        ip,
                        {"origin": "VirusTotal passive DNS", "host": a.get("host_name")},
                        "B",
                        0.5,
                        {"resolves_to": 0.7},
                        "resolved_to",
                        f"{domain} resolved to {ip} (VirusTotal)",
                    )
                )
        return out

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        return HealthResult(True, "the key works")


class SecurityTrailsAdapter(ToolAdapter):
    name = "securitytrails"
    label = "SecurityTrails"
    input_types = ["domain"]
    description = "A domain's subdomains from SecurityTrails' DNS history."
    timeout_seconds = 60

    def configured(self) -> str | None:
        return _missing("securitytrails_key", "SecurityTrails")

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        data = await fetch_json(
            f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
            params={"children_only": "false"},
            headers={"APIKEY": get_settings().securitytrails_key},
        )
        return [RawResult(self.name, domain, {"domain": domain, "subs": (data or {}).get("subdomains") or []})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        domain = raw.payload["domain"]
        return _hostnames([f"{s}.{domain}" for s in raw.payload["subs"][:200]], domain, "SecurityTrails")

    async def health_check(self) -> HealthResult:
        return await _account_ok(
            "https://api.securitytrails.com/v1/ping", headers={"APIKEY": get_settings().securitytrails_key}
        )


# --- Numverify -----------------------------------------------------------------------------------


class NumverifyAdapter(ToolAdapter):
    name = "numverify"
    label = "Numverify"
    input_types = ["phone"]
    description = "Whether a phone number is valid, and its country, carrier and line type."
    health_check_target = "14158586273"
    timeout_seconds = 30

    def configured(self) -> str | None:
        return _missing("numverify_key", "Numverify")

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        number = validate_phone(target_value)
        # The free plan only serves plain HTTP; the key is the only secret on the line.
        data = await fetch_json(
            "http://apilayer.net/api/validate", params={"access_key": get_settings().numverify_key, "number": number}
        )
        if not isinstance(data, dict):
            raise SignatureMismatch("Numverify returned an unexpected response")
        if data.get("error"):
            raise AdapterError(f"Numverify: {str((data['error'] or {}).get('info') or 'lookup failed')[:200]}")
        return [RawResult(self.name, target_value, data)]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        d = raw.payload
        attrs = {
            "valid": d.get("valid"),
            "international": d.get("international_format"),
            "country": d.get("country_name"),
            "location": d.get("location"),
            "carrier": d.get("carrier"),
            "line_type": d.get("line_type"),
        }
        return [enrich("phone", raw.target_value, "numverify", attrs)]

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        ok = bool(candidates) and candidates[0].attributes.get("numverify", {}).get("valid") is True
        return HealthResult(ok, "known number validated" if ok else "known number wasn't validated")
