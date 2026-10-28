"""Domain sources: Subfinder, DNS records and urlscan.io, and that they only ever run on domains."""

import json

import httpx
import pytest

from app.adapters import http
from app.adapters.base import AdapterError, InvalidTarget, RawResult, SignatureMismatch
from app.adapters.domain_intel import (
    DnsRecordsAdapter,
    SubfinderAdapter,
    UrlscanAdapter,
    parse_subfinder,
    services_from,
)
from app.adapters.registry import CORE_ADAPTERS
from app.pivots.rules import RULES_BY_ID


@pytest.fixture
def mock_http():
    def install(handler):
        http.transport = httpx.MockTransport(handler)

    yield install
    http.transport = None


def test_domain_sources_only_take_domains():
    # Read the shipped list, not the live registry: the app fixture swaps in fakes for the session.
    domain_tools = {c.name: c.input_types for c in CORE_ADAPTERS if c.name in {"subfinder", "dns", "urlscan"}}
    assert domain_tools == {"subfinder": ["domain"], "dns": ["domain"], "urlscan": ["domain"]}
    # Follow-ups start them only for a domain found in the case, and never on a shared provider's.
    for tool in ("subfinder", "dns", "urlscan"):
        rule = RULES_BY_ID[f"domain-{tool}"]
        assert rule.entity_type == "domain"
        assert rule.expand("gmail.com") == [] and rule.expand("github.com") == []
        assert [i.value for i in rule.expand("Acme-Corp.example")] == ["acme-corp.example"]
    with pytest.raises(InvalidTarget):
        SubfinderAdapter().build_argv("-version")
    with pytest.raises(InvalidTarget):
        SubfinderAdapter().build_argv("jane doe")


def test_subfinder_keeps_subdomains_of_the_target_with_their_sources():
    out = "\n".join(json.dumps(r) for r in [
        {"host": "www.example.com", "source": "crtsh"}, {"host": "www.example.com", "source": "alienvault"},
        {"host": "*.api.example.com", "source": "hackertarget"}, {"host": "example.com", "source": "crtsh"},
        {"host": "example.com.evil.net", "source": "x"}, {"host": "notexample.com", "source": "x"},
    ]) + "\nnot json"  # fmt: skip
    report = parse_subfinder("example.com", out, "[INF] Found 2 subdomains for example.com in 3 seconds")
    cands = SubfinderAdapter().parse(RawResult("subfinder", "example.com", report))
    assert [(c.value, c.attributes["sources"]) for c in cands] == [
        ("api.example.com", ["hackertarget"]), ("www.example.com", ["alienvault", "crtsh"])]  # fmt: skip
    assert all(c.type == "hostname" and c.relation_type == "subdomain" for c in cands)


def test_subfinder_without_its_completion_line_is_refused():
    with pytest.raises(SignatureMismatch, match="did not report completion"):
        parse_subfinder("example.com", "", "[INF] Loading provider config")


_SF_LOG = """[INF] Selected source(s) for this search: alienvault, anubis, chaos, crtsh, hackertarget, rapiddns
[DBG] Cannot use the chaos source because there was no API key/secret defined for it.
{failures}[INF] Found {n} subdomains for example.com in 4 seconds
"""


def _sf_log(failed, n=0):
    return _SF_LOG.format(
        failures="".join(f"[WRN] Encountered an error with source {s}: dial tcp: no such host\n" for s in failed), n=n
    )


def test_subfinder_that_could_not_reach_its_sources_is_refused_not_empty():
    with pytest.raises(SignatureMismatch, match="4/5 subfinder sources failed"):
        parse_subfinder("example.com", "", _sf_log(["alienvault", "anubis", "crtsh", "hackertarget"]))


def test_subfinder_empty_result_stands_when_most_sources_answered():
    report = parse_subfinder("example.com", "", _sf_log(["anubis"]))
    assert report.hosts == {} and report.tried == {"alienvault", "anubis", "crtsh", "hackertarget", "rapiddns"}


def test_subfinder_results_stand_even_when_sources_failed():
    out = '{"host":"www.example.com","source":"rapiddns"}\n'
    report = parse_subfinder("example.com", out, _sf_log(["alienvault", "anubis", "crtsh", "hackertarget"], n=1))
    assert set(report.hosts) == {"www.example.com"}


def _doh(answers: dict[tuple[str, str], list]):
    types = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "TXT": 16, "CAA": 257}

    def handler(req: httpx.Request) -> httpx.Response:
        name, rtype = req.url.params["name"], req.url.params["type"]
        rows = answers.get((name, rtype))
        if rows is None:
            return httpx.Response(200, json={"Status": 3}, headers={"content-type": "application/dns-json"})
        answer = [{"name": name, "type": types[rtype], "data": d} for d in rows]
        return httpx.Response(
            200, json={"Status": 0, "Answer": answer}, headers={"content-type": "application/dns-json"}
        )

    return handler


async def test_dns_records_say_where_a_domain_is_hosted_and_whom_it_uses(mock_http):
    mock_http(_doh({
        ("acme.example", "A"): ["93.184.216.34"], ("acme.example", "AAAA"): ["2606:2800:220:1::1"],
        ("acme.example", "MX"): ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."],
        ("acme.example", "NS"): ["ns1.dns.example."],
        ("acme.example", "TXT"): ['"v=spf1 include:_spf.google.com include:sendgrid.net ~all"',
                                  '"google-site-verification=abc"', '"atlassian-domain-verification=xyz"'],
        ("acme.example", "CAA"): [], ("_dmarc.acme.example", "TXT"): ['"v=DMARC1; p=reject"'],
    }))  # fmt: skip
    adapter = DnsRecordsAdapter()
    cands = adapter.parse((await adapter.run("acme.example", []))[0])
    info = next(c for c in cands if c.type == "domain").attributes["dns"]
    assert info["services"] == ["Atlassian", "Google Search Console", "Google Workspace", "SendGrid"]
    assert info["mail_servers"] == ["aspmx.l.google.com", "alt1.aspmx.l.google.com"]
    assert info["dmarc"] == "v=DMARC1; p=reject" and info["spf"].startswith("v=spf1")
    assert sorted(c.value for c in cands if c.type == "ip") == ["2606:2800:220:1::1", "93.184.216.34"]
    # Details attach to the domain without a score of their own.
    assert next(c for c in cands if c.type == "domain").confidence == 0.0


async def test_dns_failures_are_errors_not_empty_results(mock_http):
    mock_http(lambda req: httpx.Response(200, json={"Status": 2}, headers={"content-type": "application/dns-json"}))
    with pytest.raises(AdapterError, match="status 2"):
        await DnsRecordsAdapter().run("acme.example", [])
    mock_http(lambda req: httpx.Response(200, text="<html>blocked</html>", headers={"content-type": "text/html"}))
    with pytest.raises(SignatureMismatch):
        await DnsRecordsAdapter().run("acme.example", [])


def test_service_detection_ignores_lookalikes():
    assert services_from({"TXT": ["v=spf1 -all", "my-MS=notreally"]}) == []
    assert services_from({"MX": ["10 mx.notgoogle.com."]}) == []


def test_namecheap_private_email_is_recognised():
    records = {"MX": ["10 mx1.privateemail.com."], "TXT": ["v=spf1 include:spf.privateemail.com ~all"]}
    assert services_from(records) == ["Namecheap Private Email"]


async def test_urlscan_turns_scans_into_hostnames_and_hosting(mock_http, monkeypatch):
    from app.config import get_settings

    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["q"], seen["key"] = req.url.params["q"], req.headers.get("API-Key")
        return httpx.Response(200, json={"total": 3, "results": [
            {"task": {"time": "2026-09-01T10:00:00Z", "domain": "shop.acme.example"},
             "page": {"domain": "shop.acme.example", "ip": "203.0.113.7", "asnname": "EXAMPLE-AS", "country": "GB",
                      "title": "Acme shop"}},
            {"task": {"time": "2026-10-01T10:00:00Z"}, "page": {"domain": "shop.acme.example", "ip": "203.0.113.7"}},
            {"task": {"time": "2026-10-02T10:00:00Z"}, "page": {"domain": "cdn.other.example", "ip": "198.51.100.1"}},
        ]})  # fmt: skip

    mock_http(handler)
    monkeypatch.setattr(get_settings(), "urlscan_key", "")
    adapter = UrlscanAdapter()
    cands = adapter.parse((await adapter.run("acme.example", []))[0])
    assert seen == {"q": "domain:acme.example", "key": None}  # works without a key
    host = next(c for c in cands if c.type == "hostname")
    assert host.value == "shop.acme.example" and host.attributes["scans"] == 2
    assert (host.attributes["first_seen"], host.attributes["last_seen"]) == ("2026-09-01", "2026-10-01")
    ip = next(c for c in cands if c.type == "ip")
    assert ip.value == "203.0.113.7" and ip.attributes["country"] == "GB"
    assert not any("other.example" in c.value for c in cands)  # another site's CDN is not this domain's
    monkeypatch.setattr(get_settings(), "urlscan_key", "k-123")
    await adapter.run("acme.example", [])
    assert seen["key"] == "k-123"


async def test_urlscan_rate_limit_is_an_error(mock_http):
    mock_http(lambda req: httpx.Response(429, json={"message": "slow down"}))
    with pytest.raises(AdapterError, match="429"):
        await UrlscanAdapter().run("acme.example", [])
