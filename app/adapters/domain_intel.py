"""Domain infrastructure: subdomains (Subfinder), DNS records, and urlscan.io history.

These only take a domain. They run when a case's target is a domain, or as a
follow-up when a scan finds one (app/pivots/rules.py), never on shared mail or
platform domains (gmail.com, github.com, ...), which would describe the provider,
not the subject.
"""

from __future__ import annotations

import json
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
    validate_domain,
)
from app.adapters.lookups import enrich, fetch_json
from app.config import get_settings

# --- Subfinder ------------------------------------------------------------------------------------

_SF_DONE = re.compile(r"Found (?P<n>\d+) subdomains? for (?P<domain>\S+)")
_SF_SELECTED = re.compile(r"Selected source\(s\) for this search: (?P<names>.+)$")
_SF_NO_KEY = re.compile(r"Cannot use the (?P<source>\S+) source because there was no API key")
_SF_FAILED = re.compile(r"Encountered an error with source (?P<source>[\w-]+)")
SF_MAX_FAILED_RATIO = 0.5


@dataclass
class SubfinderReport:
    domain: str
    hosts: dict[str, set] = field(default_factory=dict)  # host -> sources that reported it
    tried: set = field(default_factory=set)  # sources that ran (selected, minus those missing a key)
    failed: set = field(default_factory=set)


def parse_subfinder(domain: str, stdout: str, stderr: str) -> SubfinderReport:
    log = strip_ansi(stderr)
    if not _SF_DONE.search(log):
        raise SignatureMismatch("subfinder did not report completion (run was cut short)")
    report = SubfinderReport(domain)
    selected: set = set()
    no_key: set = set()
    for line in log.splitlines():
        if m := _SF_SELECTED.search(line):
            selected = {n.strip() for n in m["names"].split(",") if n.strip()}
        elif m := _SF_NO_KEY.search(line):
            no_key.add(m["source"])
        elif m := _SF_FAILED.search(line):
            report.failed.add(m["source"])
    report.tried = (selected - no_key) or set(report.failed)
    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        host = str(row.get("host") or "").strip().lower().rstrip(".")
        if host.startswith("*."):
            host = host[2:]
        if host and host != domain and host.endswith("." + domain):
            report.hosts.setdefault(host, set()).add(str(row.get("source") or "subfinder"))
    if not report.hosts and report.tried:
        failed = len(report.failed & report.tried)
        if failed / len(report.tried) > SF_MAX_FAILED_RATIO:
            raise SignatureMismatch(
                f"{failed}/{len(report.tried)} subfinder sources failed; "
                "an empty result would not mean there are no subdomains"
            )
    return report


class SubfinderAdapter(ToolAdapter):
    name = "subfinder"
    label = "Subfinder"
    input_types = ["domain"]
    description = (
        "Passive subdomain discovery from dozens of public sources (certificate logs, DNS datasets, archives), "
        "without touching the domain itself."
    )
    health_check_target = "example.com"
    timeout_seconds = 300
    speed = "slow"

    def build_argv(self, domain: str) -> list[str]:
        domain = validate_domain(domain)
        return [
            resolve_binary("subfinder"),
            "-d",
            domain,
            "-oJ",
            "-nc",
            "-timeout",
            "30",
            "-max-time",
            "4",
            "-disable-update-check",
            "-v",  # verbose: lists the sources tried and the ones that failed, so a blind run is caught
        ]

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        proc = await run_tool_subprocess(self.build_argv(domain), timeout=self.timeout_seconds, tool=self.name)
        if proc.returncode != 0:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
            raise AdapterError(f"subfinder exited with code {proc.returncode}: {strip_ansi(tail[0])[:300]}")
        return [RawResult(self.name, domain, parse_subfinder(domain, proc.stdout, proc.stderr))]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        r: SubfinderReport = raw.payload
        return [
            EntityCandidate(
                type="hostname",
                value=host,
                attributes={"domain": r.domain, "sources": sorted(sources)},
                source_reliability="B",
                confidence=0.6,
                field_confidence={"belongs_to_domain": 0.85},
                relation_type="subdomain",
                relation_explanation=f"reported by {len(sources)} passive source(s): {', '.join(sorted(sources)[:5])}",
            )
            for host, sources in sorted(r.hosts.items())
        ]

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        # example.com has few public subdomains; a completed run is the signal, not the count.
        return HealthResult(True, f"run completed, {len(candidates)} subdomains for example.com")


# --- DNS records ----------------------------------------------------------------------------------

DOH = "https://cloudflare-dns.com/dns-query"
RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CAA")
_TYPE_NO = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 15: "MX", 16: "TXT", 28: "AAAA", 257: "CAA"}

# What a domain's records say about the services its owner uses.
MAIL_PROVIDERS = {
    "privateemail.com": "Namecheap Private Email",
    "google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "outlook.com": "Microsoft 365",
    "protection.outlook.com": "Microsoft 365",
    "zoho.com": "Zoho Mail",
    "zoho.eu": "Zoho Mail",
    "protonmail.ch": "Proton Mail",
    "icloud.com": "iCloud Mail",
    "messagingengine.com": "Fastmail",
    "mx.cloudflare.net": "Cloudflare Email Routing",
    "improvmx.com": "ImprovMX",
    "mailgun.org": "Mailgun",
    "secureserver.net": "GoDaddy Email",
    "yandex.net": "Yandex Mail",
    "migadu.com": "Migadu",
}
TXT_SERVICES = {
    "google-site-verification=": "Google Search Console",
    "MS=": "Microsoft 365",
    "facebook-domain-verification=": "Meta (Facebook)",
    "apple-domain-verification=": "Apple",
    "atlassian-domain-verification=": "Atlassian",
    "stripe-verification=": "Stripe",
    "adobe-idp-site-verification=": "Adobe",
    "docusign=": "DocuSign",
    "zoom-verification=": "Zoom",
    "slack-domain-verification=": "Slack",
    "github-verification": "GitHub",
    "_github-challenge": "GitHub",
    "openai-domain-verification=": "OpenAI",
    "hubspot-developer-verification=": "HubSpot",
    "notion-domain-verification=": "Notion",
    "canva-site-verification=": "Canva",
    "brevo-code:": "Brevo",
    "mailchimp": "Mailchimp",
    "have-i-been-pwned-verification=": "Have I Been Pwned",
    "keybase-site-verification=": "Keybase",
    "dropbox-domain-verification=": "Dropbox",
}
SPF_SERVICES = {
    "spf.privateemail.com": "Namecheap Private Email",
    "_spf.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "zoho": "Zoho Mail",
    "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid",
    "amazonses.com": "Amazon SES",
    "servers.mcsv.net": "Mailchimp",
    "_spf.mx.cloudflare.net": "Cloudflare Email Routing",
    "spf.messagingengine.com": "Fastmail",
    "protonmail.ch": "Proton Mail",
    "spf.brevo.com": "Brevo",
}


async def resolve(name: str, rtype: str) -> list[str]:
    """DNS over HTTPS (Cloudflare's JSON API): the record values, [] for none. Failures raise."""
    data = await fetch_json(
        DOH, params={"name": name, "type": rtype}, headers={"Accept": "application/dns-json"}, timeout=15
    )
    if not isinstance(data, dict) or "Status" not in data:
        raise SignatureMismatch("the DNS resolver returned an unexpected answer")
    if data["Status"] == 3:  # NXDOMAIN
        return []
    if data["Status"] != 0:
        raise AdapterError(f"DNS lookup for {rtype} {name} failed (status {data['Status']})")
    want = {k for k, v in _TYPE_NO.items() if v == rtype}
    return [str(a.get("data", "")).strip().strip('"') for a in data.get("Answer") or [] if a.get("type") in want]


def services_from(records: dict[str, list[str]]) -> list[str]:
    found = []
    for mx in records.get("MX", []):
        host = mx.split()[-1].rstrip(".").lower() if mx else ""
        found += [v for k, v in MAIL_PROVIDERS.items() if host == k or host.endswith("." + k)]
    for txt in records.get("TXT", []):
        # Verification tokens are prefixes ("google-site-verification=..."); the rest are names inside the record.
        found += [v for k, v in TXT_SERVICES.items() if (txt.startswith(k) if k[-1] in "=:" else k in txt)]
        if txt.startswith("v=spf1"):
            found += [v for k, v in SPF_SERVICES.items() if k in txt]
    return sorted(set(found))


class DnsRecordsAdapter(ToolAdapter):
    name = "dns"
    label = "DNS records"
    input_types = ["domain"]
    description = (
        "A domain's public DNS: where it is hosted, who handles its email, and which services it has verified "
        "ownership with (Google, Microsoft, Atlassian, ...)."
    )
    health_check_target = "example.com"
    timeout_seconds = 60

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        records = {t: await resolve(domain, t) for t in RECORD_TYPES}
        records["DMARC"] = [r for r in await resolve(f"_dmarc.{domain}", "TXT") if r.startswith("v=DMARC1")]
        return [RawResult(self.name, domain, {"domain": domain, "records": records})]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        domain, rec = raw.payload["domain"], raw.payload["records"]
        out = [
            enrich(
                "domain",
                domain,
                "dns",
                {
                    "mail_servers": [m.split()[-1].rstrip(".") for m in rec.get("MX", []) if m][:10],
                    "name_servers": [n.rstrip(".") for n in rec.get("NS", [])][:10],
                    "services": services_from(rec),
                    "spf": next((t for t in rec.get("TXT", []) if t.startswith("v=spf1")), None),
                    "dmarc": (rec.get("DMARC") or [None])[0],
                    "txt_records": len(rec.get("TXT", [])),
                },
            )
        ]
        for rtype in ("A", "AAAA"):
            for ip in rec.get(rtype, [])[:10]:
                out.append(
                    EntityCandidate(
                        "ip",
                        ip,
                        {"record": rtype, "domain": domain},
                        "A",
                        0.5,
                        {"belongs_to_domain": 0.95},
                        "resolves_to",
                        f"{domain} has a DNS {rtype} record pointing here",
                    )
                )
        return out

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        ips = [c for c in candidates if c.type == "ip"]
        if ips:
            return HealthResult(True, f"example.com resolved to {len(ips)} address(es)")
        return HealthResult(False, "example.com did not resolve")


# --- urlscan.io -----------------------------------------------------------------------------------


class UrlscanAdapter(ToolAdapter):
    name = "urlscan"
    label = "urlscan.io"
    input_types = ["domain"]
    description = (
        "Public urlscan.io scans of a domain: its hostnames, the servers and IP addresses that hosted it, page "
        "titles, and when they were seen. Works without a key; a free key raises the limits."
    )
    health_check_target = "example.com"
    timeout_seconds = 60

    async def run(self, target_value: str, context_tags: list[str]) -> list[RawResult]:
        domain = validate_domain(target_value)
        key = get_settings().urlscan_key
        data = await fetch_json(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 100},
            headers={"API-Key": key} if key else None,
        )
        if not isinstance(data, dict) or "results" not in data:
            raise SignatureMismatch("urlscan.io returned an unexpected search result")
        return [
            RawResult(self.name, domain, {"domain": domain, "results": data["results"], "total": data.get("total")})
        ]

    def parse(self, raw: RawResult) -> list[EntityCandidate]:
        domain = raw.payload["domain"]
        hosts: dict[str, dict] = {}
        ips: dict[str, dict] = {}
        for r in raw.payload["results"]:
            page, task = r.get("page") or {}, r.get("task") or {}
            when = str(task.get("time") or "")[:10] or None
            host = str(page.get("domain") or task.get("domain") or "").lower().rstrip(".")
            if host and host != domain and host.endswith("." + domain):
                h = hosts.setdefault(host, {"scans": 0, "first": when, "last": when, "titles": set()})
                h["scans"] += 1
                h["first"] = min(filter(None, [h["first"], when]), default=None)
                h["last"] = max(filter(None, [h["last"], when]), default=None)
                if page.get("title"):
                    h["titles"].add(str(page["title"])[:120])
            if page.get("ip") and (host == domain or host.endswith("." + domain)):
                i = ips.setdefault(
                    page["ip"],
                    {
                        "asn": page.get("asnname"),
                        "country": page.get("country"),
                        "server": page.get("server"),
                        "last": when,
                        "hosts": set(),
                    },
                )
                i["last"] = max(filter(None, [i["last"], when]), default=None)
                i["hosts"].add(host)
        out = [
            EntityCandidate(
                "hostname",
                host,
                {
                    "domain": domain,
                    "scans": h["scans"],
                    "first_seen": h["first"],
                    "last_seen": h["last"],
                    "titles": sorted(h["titles"])[:3],
                },
                "B",
                0.6,
                {"belongs_to_domain": 0.85},
                "subdomain",
                f"seen in {h['scans']} public urlscan.io scan(s)",
            )
            for host, h in sorted(hosts.items())
        ]
        out += [
            EntityCandidate(
                "ip",
                ip,
                {
                    "domain": domain,
                    "asn": i["asn"],
                    "country": i["country"],
                    "server": i["server"],
                    "last_seen": i["last"],
                    "hosts": sorted(i["hosts"])[:5],
                },
                "B",
                0.45,
                {"belongs_to_domain": 0.7},
                "hosted_on",
                f"served {', '.join(sorted(i['hosts'])[:3])} in a urlscan.io scan",
            )
            for ip, i in sorted(ips.items())
        ]
        return out

    def check_health_output(self, candidates: list[EntityCandidate]) -> HealthResult:
        return HealthResult(True, f"search answered, {len(candidates)} results for example.com")


DOMAIN_ADAPTERS = (SubfinderAdapter, DnsRecordsAdapter, UrlscanAdapter)
