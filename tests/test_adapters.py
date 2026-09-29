"""Parser and signature tests for every core adapter.

Fixtures are trimmed from real tool output, including runs where every source
was blocked — the case each adapter must report as a failure, not "nothing found".
"""

import json
import stat
import sys

import httpx
import pytest

from app.adapters import http
from app.adapters.amass import AmassAdapter
from app.adapters.amass import parse_output as parse_amass
from app.adapters.base import (
    AdapterError,
    InvalidTarget,
    RawResult,
    SignatureMismatch,
    run_tool_subprocess,
    validate_domain,
    validate_email,
)
from app.adapters.crtsh import CrtShAdapter
from app.adapters.h8mail import H8mailAdapter, parse_keys
from app.adapters.h8mail import parse_output as parse_h8mail
from app.adapters.holehe import HoleheAdapter
from app.adapters.holehe import parse_output as parse_holehe
from app.adapters.maigret import MaigretAdapter
from app.adapters.maigret import parse_output as parse_maigret
from app.adapters.spiderfoot import SpiderFootAdapter
from app.adapters.spiderfoot import parse_output as parse_spiderfoot
from app.adapters.theharvester import TheHarvesterAdapter
from app.adapters.theharvester import parse_output as parse_harvester
from app.config import get_settings

# --- Input validation ----------------------------------------------------------


@pytest.mark.parametrize("bad", ["-x@example.com", "a b@example.com", "x@", "x@-evil.com", "x@ex ample.com", ""])
def test_rejects_unsafe_emails(bad):
    with pytest.raises(InvalidTarget):
        validate_email(bad)


@pytest.mark.parametrize("bad", ["-d", "example", "exa mple.com", "example.com;id", "http://example.com"])
def test_rejects_unsafe_domains(bad):
    with pytest.raises(InvalidTarget):
        validate_domain(bad)


def test_domain_is_normalised():
    assert validate_domain(" Example.COM. ") == "example.com"


# --- Subprocess sandbox --------------------------------------------------------


async def test_subprocess_gets_scrubbed_env_and_private_files(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://secret")
    monkeypatch.setenv("UNMASK_DATA_KEYS", "secret-key")
    script = (
        "import os, json, stat;"
        "leaked = [k for k in os.environ if k in ('DATABASE_URL', 'UNMASK_DATA_KEYS', 'SECRET_KEY')];"
        "mode = stat.S_IMODE(os.stat('cfg.ini').st_mode);"
        "cfg = open('cfg.ini').read();"
        "open('out/result.json', 'w').write(json.dumps({'leaked': leaked, 'mode': mode, 'cfg': cfg}))"
    )
    proc = await run_tool_subprocess(
        [sys.executable, "-c", "import os; os.mkdir('out'); " + script],
        files_in={"cfg.ini": "[x]\nkey = 1\n"},
        collect=["out/*.json"],
    )
    result = json.loads(proc.files["out/result.json"])
    assert result["leaked"] == []
    assert result["mode"] == stat.S_IRUSR | stat.S_IWUSR
    assert result["cfg"] == "[x]\nkey = 1\n"


async def test_subprocess_timeout_is_an_adapter_error():
    with pytest.raises(AdapterError, match="timed out"):
        await run_tool_subprocess([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)


async def test_missing_binary_is_an_adapter_error():
    with pytest.raises(AdapterError, match="not installed"):
        await run_tool_subprocess(["/nonexistent/tool"])


# --- Maigret -------------------------------------------------------------------

MAIGRET_OK = """[+] Using sites database: /root/.maigret/data.json (6206 sites)
[-] Starting a search on top 4 sites from the Maigret database...
[*] Checking username torvalds on:
[+] GitHub: https://github.com/torvalds
[+] GitHubGist [GitHub]: https://gist.github.com/torvalds
[?] Vimeo: Unexpected error: 403
[*] Short text report:
Search by username torvalds returned 2 accounts.
"""
MAIGRET_NDJSON = "\n".join(
    json.dumps(
        {
            "sitename": site,
            "url_user": url,
            "status": {"url": url, "status": "Claimed", "ids": ids, "tags": ["coding"]},
        }
    )
    for site, url, ids in [
        ("GitHub", "https://github.com/torvalds", {"fullname": "Linus Torvalds", "follower_count": "1"}),
        ("GitHubGist", "https://gist.github.com/torvalds", {}),
    ]
)

MAIGRET_BLOCKED = (
    """[-] Starting a search on top 23 sites from the Maigret database...
[*] Checking username torvalds on:
"""
    + "\n".join(f"[?] Site{i}: Unexpected error: 403, message='Forbidden'" for i in range(20))
    + """
[+] GitHubGist [GitHub]: https://gist.github.com/torvalds
[!] Too many errors of type "Unexpected" (86.96%)
Search by username torvalds returned 1 accounts.
"""
)


def test_maigret_parses_accounts_and_keeps_only_profile_fields():
    report = parse_maigret(MAIGRET_OK, MAIGRET_NDJSON)
    assert report.sites_checked == 4 and len(report.errored) == 1
    cands = MaigretAdapter().parse(RawResult("maigret", "torvalds", report))
    github = next(c for c in cands if c.attributes["site"] == "GitHub")
    assert github.attributes["profile"] == {"fullname": "Linus Torvalds"}
    assert github.confidence > next(c for c in cands if c.attributes["site"] == "GitHubGist").confidence
    assert all(c.source_reliability == "C" and c.type == "account" for c in cands)


def test_maigret_blocked_run_is_a_signature_mismatch():
    with pytest.raises(SignatureMismatch, match="20/23 sites errored"):
        parse_maigret(MAIGRET_BLOCKED, "{}")


def test_maigret_report_count_must_match():
    with pytest.raises(SignatureMismatch, match="report holds 1"):
        parse_maigret(MAIGRET_OK, MAIGRET_NDJSON.splitlines()[0])


def test_maigret_argv_never_recurses_and_ends_with_username(monkeypatch):
    monkeypatch.setattr("app.adapters.maigret.resolve_binary", lambda n: "/bin/maigret")
    argv = MaigretAdapter().build_argv("torvalds")
    assert "--no-recursion" in argv and argv[-2:] == ["--", "torvalds"]


# --- Holehe --------------------------------------------------------------------


def holehe_output(used=(), not_used=(), limited=(), total=None):
    lines = ["********************", "   x@example.com", "********************"]
    lines += [f"[+] {s}" for s in used] + [f"[-] {s}" for s in not_used] + [f"[x] {s}" for s in limited]
    total = total if total is not None else len(used) + len(not_used) + len(limited)
    lines += ["", "[+] Email used, [-] Email not used, [x] Rate limit", f"{total} websites checked in 0.38 seconds"]
    return "\n".join(lines)


def test_holehe_parses_registrations():
    out = holehe_output(used=["github.com", "spotify.com"], not_used=[f"s{i}.com" for i in range(30)])
    report = parse_holehe("x@example.com", out)
    cands = HoleheAdapter().parse(RawResult("holehe", "x@example.com", report))
    assert [c.attributes["site"] for c in cands] == ["github.com", "spotify.com"]
    assert all(c.type == "registration" and c.source_reliability == "B" for c in cands)


def test_holehe_all_rate_limited_is_a_mismatch():
    # Real sandbox output: 117 sites, every one "[x]".
    with pytest.raises(SignatureMismatch, match="117/117 sites rate-limited"):
        parse_holehe("x@example.com", holehe_output(limited=[f"s{i}.com" for i in range(117)]))


def test_holehe_truncated_run_is_a_mismatch():
    with pytest.raises(SignatureMismatch, match="did not report completion"):
        parse_holehe("x@example.com", "[+] github.com\n[-] a.com\n")


def test_holehe_never_uses_password_recovery(monkeypatch):
    monkeypatch.setattr("app.adapters.holehe.resolve_binary", lambda n: "/bin/holehe")
    assert "--no-password-recovery" in HoleheAdapter().build_argv("x@example.com")


# --- h8mail --------------------------------------------------------------------


def test_h8mail_refuses_to_run_without_keys(monkeypatch):
    monkeypatch.setattr(get_settings(), "h8mail_keys", "")
    adapter = H8mailAdapter()
    assert "No breach source" in adapter.configured() and "Integrations page" in adapter.configured()


def test_h8mail_keys_are_filtered_and_go_to_a_config_file(monkeypatch):
    assert parse_keys("hibp=abc, bogus=1, snusbase_token = t ,broken") == {"hibp": "abc", "snusbase_token": "t"}
    monkeypatch.setattr(get_settings(), "h8mail_keys", "hibp=abc")
    adapter = H8mailAdapter()
    assert adapter.configured() is None
    assert adapter.build_config() == "[h8mail]\nhibp = abc\n"
    monkeypatch.setattr("app.adapters.h8mail.resolve_binary", lambda n: "/bin/h8mail")
    assert "abc" not in " ".join(adapter.build_argv("x@example.com"))


H8_RECAP = "  Session Recap:  \n  x@example.com | Compromised\n"


def test_h8mail_redacts_credentials_and_extracts_pivots():
    report_json = json.dumps(
        {
            "targets": [
                {
                    "target": "x@example.com",
                    "pwn_num": 3,
                    "data": [
                        ["HIBP3:LinkedIn", "HIBP3:Adobe"],
                        ["SNUS_USERNAME:jdoe", "SNUS_PASSWORD:hunter2", "SNUS_HASH:5f4dcc3b", "SNUS_SOURCE:acme.com"],
                    ],
                }
            ]
        }
    )
    report = parse_h8mail("x@example.com", H8_RECAP, report_json)
    cands = H8mailAdapter().parse(RawResult("h8mail", "x@example.com", report))
    breaches = {c.value: c for c in cands if c.type == "breach"}
    assert set(breaches) == {"LinkedIn (HIBP3)", "Adobe (HIBP3)", "acme.com (SNUS)"}
    assert breaches["LinkedIn (HIBP3)"].source_reliability == "B"
    snus = breaches["acme.com (SNUS)"]
    assert snus.source_reliability == "D"
    assert snus.attributes["credential_exposed"] is True
    blob = json.dumps([c.attributes for c in cands])
    assert "hunter2" not in blob and "5f4dcc3b" not in blob
    assert {c["kind"] for c in snus.attributes["credentials"]} == {"password", "hash"}
    import hashlib

    plain_sha = hashlib.sha256(b"hunter2").hexdigest()[:12]
    assert plain_sha not in blob  # fingerprint is keyed, not a bare hash
    assert [(c.type, c.value) for c in cands if c.type == "username"] == [("username", "jdoe")]


def test_h8mail_source_errors_without_findings_are_a_mismatch():
    out = H8_RECAP + "[!] Could not contact HIBP v3 for x@example.com\n"
    report_json = json.dumps({"targets": [{"target": "x@example.com", "pwn_num": 0, "data": []}]})
    with pytest.raises(SignatureMismatch, match="can't be trusted"):
        parse_h8mail("x@example.com", out, report_json)


def test_h8mail_clean_negative_is_accepted():
    report_json = json.dumps({"targets": [{"target": "x@example.com", "pwn_num": 0, "data": []}]})
    assert parse_h8mail("x@example.com", H8_RECAP, report_json).records == []


# --- theHarvester --------------------------------------------------------------

HARVESTER_BLOCKED = """[*] Target: example.com
An exception has occurred: Cannot connect to host api.hackertarget.com:443 ssl:True
An exception has occurred: Cannot connect to host api.hackertarget.com:443 ssl:True
\x1b[94m[*] Searching Hackertarget.
An exception has occurred: Cannot connect to host crt.sh:443 ssl:True
\x1b[94m[*] Searching CRTsh.
[*] No hosts found.
[*] Reporting started.
[*] JSON File saved.
"""
HARVESTER_OK = """[*] Target: example.com
\x1b[94m[*] Searching CRTsh.
\x1b[94m[*] Searching Hackertarget.
An exception has occurred: timeout
[*] JSON File saved.
"""


def test_harvester_all_sources_failing_is_a_mismatch_even_with_a_clean_report():
    empty = json.dumps({"cmd": "-d example.com", "hosts": [], "shodan": []})
    with pytest.raises(SignatureMismatch, match="3 source exception"):
        parse_harvester("example.com", HARVESTER_BLOCKED, empty)


def test_harvester_parses_emails_hosts_ips():
    data = {
        "emails": ["Info@Example.com", "not-an-email"],
        "hosts": ["www.example.com:93.184.216.34", "mail.example.com", "www.example.com:93.184.216.35"],
        "ips": ["93.184.216.34"],
    }
    report = parse_harvester("example.com", HARVESTER_OK, json.dumps(data))
    assert report.emails == ["info@example.com"]
    assert report.hosts == {"www.example.com": ["93.184.216.34", "93.184.216.35"], "mail.example.com": []}
    cands = TheHarvesterAdapter().parse(RawResult("theharvester", "example.com", report))
    assert {c.type for c in cands} == {"email", "hostname", "ip"}


def test_harvester_without_report_is_a_mismatch():
    with pytest.raises(SignatureMismatch, match="no JSON report"):
        parse_harvester("example.com", HARVESTER_OK, None)


def test_harvester_sources_setting_is_sanitised(monkeypatch):
    monkeypatch.setattr(get_settings(), "harvester_sources", "crtsh, bad;source ,otx")
    assert TheHarvesterAdapter().sources() == "crtsh,otx"


# --- crt.sh --------------------------------------------------------------------


@pytest.fixture
def mock_http():
    def install(handler):
        http.transport = httpx.MockTransport(handler)

    yield install
    http.transport = None


async def test_crtsh_collapses_certificates_into_hostnames(mock_http):
    rows = [
        {"name_value": "www.example.com\n*.example.com", "common_name": "example.com", "not_before": "2024-01-01"},
        {"name_value": "api.example.com", "common_name": "api.example.com", "issuer_name": "C=US, O=LE"},
        {"name_value": "evil.com", "common_name": "evil.com"},
    ]
    mock_http(lambda req: httpx.Response(200, json=rows))
    adapter = CrtShAdapter()
    raws = await adapter.run("example.com", [])
    cands = adapter.parse(raws[0])
    assert sorted(c.value for c in cands) == ["api.example.com", "www.example.com"]
    assert all(c.source_reliability == "B" for c in cands)


async def test_crtsh_html_200_is_a_mismatch(mock_http):
    mock_http(
        lambda req: httpx.Response(200, text="<html>Too many requests</html>", headers={"content-type": "text/html"})
    )
    with pytest.raises(SignatureMismatch, match="instead of JSON"):
        await CrtShAdapter().run("example.com", [])


async def test_crtsh_http_error_is_an_adapter_error(mock_http):
    mock_http(lambda req: httpx.Response(502, text="Bad gateway"))
    with pytest.raises(AdapterError, match="HTTP 502"):
        await CrtShAdapter().run("example.com", [])


# --- Amass ---------------------------------------------------------------------


AMASS_DONE = "example.com\n\nThe enumeration has finished\nDiscoveries are being migrated into the local database\n"


def amass_log(ok=(), failed=(), unconfigured=("Chaos", "Hunter")):
    lines = [f"08:57:07.04 {s}: check callback failed for the configuration" for s in unconfigured]
    for src in (*ok, *failed):
        lines.append(f"08:57:08.10 Querying {src} for example.com subdomains")
    lines += [f'08:57:09.20 {src}: scrape: Get "https://{src.lower()}.example/": Forbidden' for src in failed]
    return "\n".join(lines)


def test_amass_parses_json_lines():
    lines = "\n".join(
        json.dumps(r)
        for r in [
            {"name": "www.example.com", "addresses": [{"ip": "1.2.3.4"}], "sources": ["Crtsh"]},
            {"name": "www.example.com", "addresses": [{"ip": "1.2.3.4"}], "sources": ["DNS"]},
            {"name": "example.com", "addresses": None, "sources": ["DNS"]},
            {"name": "other.org"},
        ]
    )
    report = parse_amass("example.com", lines, AMASS_DONE, amass_log(ok=["Crtsh", "DNS"], failed=["Yahoo"]))
    assert sorted(report.names) == ["example.com", "www.example.com"]
    assert report.names["www.example.com"]["sources"] == ["Crtsh", "DNS"]
    assert report.source_errors.keys() == {"Yahoo"}
    assert [c.value for c in AmassAdapter().parse(RawResult("amass", "example.com", report))] == ["www.example.com"]


def test_amass_mostly_blocked_sources_is_a_mismatch():
    # Real sandbox run: every public source answered 403 and only the apex came back.
    log = amass_log(ok=["DNS"], failed=["Yahoo", "Wayback", "URLScan", "RapidDNS"])
    apex = json.dumps({"name": "example.com", "sources": ["DNS"]})
    with pytest.raises(SignatureMismatch, match="4/5 data sources failed"):
        parse_amass("example.com", apex, AMASS_DONE, log)


def test_amass_unconfigured_api_sources_are_not_failures():
    report = parse_amass("example.com", "", AMASS_DONE, amass_log(ok=["Crtsh"]))
    assert report.source_errors == {} and report.names == {}


def test_amass_without_completion_is_a_mismatch():
    with pytest.raises(SignatureMismatch, match="completion"):
        parse_amass("example.com", None, "", None)


# --- SpiderFoot ----------------------------------------------------------------

SF_FAILED_STDERR = """2026-09-26 08:44:54,556 [ERROR] sflib : Unable to open option URL
2026-09-26 08:44:54,556 [INFO] sflib : Scan [8B031982] failed: Could not update TLD list
ValueError: Could not update TLD list
2026-09-26 08:44:55,143 [INFO] sf : Scan completed with status ERROR-FAILED
"""


def test_spiderfoot_failed_scan_printing_empty_list_is_a_mismatch():
    # Real behaviour: exit code 0, stdout "[]".
    with pytest.raises(SignatureMismatch, match="ERROR-FAILED"):
        parse_spiderfoot("example.com", "[]\n", SF_FAILED_STDERR)


def test_spiderfoot_maps_identity_types_only():
    events = [
        {"type": "Internet Name", "data": "WWW.example.com", "module": "sfp_dnsresolve"},
        {"type": "Internet Name", "data": "www.example.com", "module": "sfp_crt"},
        {"type": "Email Address", "data": "info@example.com", "module": "sfp_email"},
        {"type": "Raw DNS Records", "data": "blob", "module": "sfp_dns"},
        {"type": "Domain Name", "data": "example.com", "module": "sfp_dns"},
    ]
    stderr = "[ERROR] sfp_shodan : no key\nScan completed with status FINISHED\n"
    report = parse_spiderfoot("example.com", json.dumps(events), stderr)
    cands = SpiderFootAdapter().parse(RawResult("spiderfoot", "example.com", report))
    assert sorted((c.type, c.value) for c in cands) == [("email", "info@example.com"), ("hostname", "www.example.com")]
    host = next(c for c in cands if c.type == "hostname")
    assert host.attributes["modules"] == ["sfp_dnsresolve", "sfp_crt"]
    assert host.attributes["module_errors"] == ["sfp_shodan"]


def test_spiderfoot_accepts_ip_targets(monkeypatch):
    monkeypatch.setattr("app.adapters.spiderfoot.resolve_binary", lambda n: "/bin/spiderfoot")
    assert SpiderFootAdapter().build_argv("93.184.216.34")[2] == "93.184.216.34"
    with pytest.raises(InvalidTarget):
        SpiderFootAdapter().build_argv("-h")


def test_core_adapters_are_unique_and_cover_target_types():
    from app.adapters.registry import CORE_ADAPTERS

    names = [cls.name for cls in CORE_ADAPTERS]
    assert len(names) == len(set(names)) == 26
    covered = {t for cls in CORE_ADAPTERS for t in cls.input_types}
    assert {"username", "email", "domain", "ip"} <= covered
