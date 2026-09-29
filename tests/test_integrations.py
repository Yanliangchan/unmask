"""Integration keys entered in the app, and the API lookup tools that use them."""

import json
import uuid

import httpx
import pytest
from sqlalchemy import delete, select, text

from app import integrations
from app.adapters import http
from app.adapters.keyed import (
    EmailRepAdapter,
    HibpAdapter,
    HunterAdapter,
    IpinfoAdapter,
    NumverifyAdapter,
    ShodanAdapter,
    VirusTotalAdapter,
)
from app.adapters.lookups import (
    GitHubAdapter,
    GitLabAdapter,
    GravatarAdapter,
    HackerNewsAdapter,
    KeybaseAdapter,
    LeakCheckAdapter,
    RdapAdapter,
    WaybackAdapter,
)
from app.config import get_settings
from app.models import AccessLog, AppSecret, User
from app.security import hash_password
from tests.conftest import login


@pytest.fixture
async def clean_secrets(db):
    yield
    await db.execute(delete(AppSecret))
    await db.commit()
    await integrations.refresh(db, force=True)


async def test_admin_saves_a_key_that_is_encrypted_masked_and_used(client, db, clean_secrets):
    csrf = await login(client)
    assert get_settings().hunter_key == ""
    page = (await client.get("/integrations")).text
    assert "Hunter" in page and "Not set up" in page and "Get a key" in page

    r = await client.post("/integrations/hunter", data={"csrf_token": csrf, "hunter_key": "hk_live_abcdef123456"})
    assert r.headers["location"].startswith("/integrations?saved=saved")
    assert get_settings().hunter_key == "hk_live_abcdef123456"
    assert HunterAdapter().configured() is None
    raw = await db.scalar(text("SELECT value FROM app_secrets WHERE name = 'hunter_key'"))
    assert "hk_live" not in raw  # encrypted at rest
    page = (await client.get("/integrations")).text
    assert "hk_live_abcdef123456" not in page and "••••••3456" in page and "saved here" in page
    log = await db.scalar(
        select(AccessLog).where(AccessLog.action == "integration_update").order_by(AccessLog.timestamp.desc())
    )
    assert log.detail == {"integration": "hunter", "settings": ["hunter_key"]} and "hk_live" not in json.dumps(
        log.detail
    )

    # A blank field keeps the saved key; Remove clears it.
    await client.post("/integrations/hunter", data={"csrf_token": csrf, "hunter_key": ""})
    assert get_settings().hunter_key == "hk_live_abcdef123456"
    await client.post("/integrations/hunter", data={"csrf_token": csrf, "remove": "1"})
    assert get_settings().hunter_key == "" and "needs an API key" in HunterAdapter().configured()


async def test_bad_values_are_refused_and_only_admins_can_change_keys(client, db, clean_secrets):
    csrf = await login(client)
    bad = await client.post("/integrations/proxy", data={"csrf_token": csrf, "proxy_url": "ftp://nope"})
    assert bad.status_code == 422 and "proxy URL must look like" in bad.text
    spaced = await client.post("/integrations/shodan", data={"csrf_token": csrf, "shodan_key": "abc def"})
    assert spaced.status_code == 422
    await client.post("/logout", data={"csrf_token": csrf})

    email = f"analyst-{uuid.uuid4().hex[:8]}@example.com"
    db.add(User(email=email, password_hash=hash_password("analyst-password-1")))
    await db.commit()
    csrf = await login(client, email, "analyst-password-1")
    page = (await client.get("/integrations")).text
    assert "Only an administrator can change them" in page and 'name="shodan_key"' not in page
    denied = await client.post("/integrations/shodan", data={"csrf_token": csrf, "shodan_key": "abc"})
    assert denied.status_code == 403 and get_settings().shodan_key == ""


async def test_keys_saved_elsewhere_reach_this_process_on_refresh(db, clean_secrets):
    db.add(AppSecret(name="shodan_key", value="from-another-process"))
    await db.commit()
    await integrations.refresh(db, force=True)
    assert get_settings().shodan_key == "from-another-process" and integrations.source_of("shodan_key") == "app"


# --- Adapters, against mocked APIs --------------------------------------------------------------


@pytest.fixture
def api(monkeypatch):
    routes: dict[str, object] = {}
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        for prefix, body in routes.items():
            if f"{req.url.host}{req.url.path}".startswith(prefix):
                if isinstance(body, int):
                    return httpx.Response(body, json={"message": "nope"})
                return httpx.Response(200, json=body)
        return httpx.Response(404, json={"message": "Not Found"})

    http.transport = httpx.MockTransport(handler)
    yield routes, seen
    http.transport = None


async def _run(adapter, value):
    raws = await adapter.run(value, [])
    return [c for raw in raws for c in adapter.parse(raw)]


async def test_github_profile_links_and_commit_authors(api):
    routes, seen = api
    routes["api.github.com/users/yanliangchan/social_accounts"] = [
        {"provider": "linkedin", "url": "https://www.linkedin.com/in/yanliangchan"}
    ]
    routes["api.github.com/users/yanliangchan"] = {
        "login": "yanliangchan",
        "name": "Yan Liang Chan",
        "location": "Singapore",
        "blog": "yanliang.dev",
        "twitter_username": "yanliangchan",
        "bio": "Security. Mail me: yl@yanliang.dev",
        "html_url": "https://github.com/yanliangchan",
    }
    routes["api.github.com/search/commits"] = {"items": [{"author": {"login": "yanliangchan"}}]}
    found = await _run(GitHubAdapter(), "yanliangchan")
    acct = next(c for c in found if c.value == "https://github.com/yanliangchan")
    assert acct.attributes["verification"] == "verified" and acct.attributes["profile"]["name"] == "Yan Liang Chan"
    assert "https://x.com/yanliangchan" in acct.attributes["preview"]["links"]
    assert {c.value for c in found} >= {
        "https://x.com/yanliangchan",
        "https://www.linkedin.com/in/yanliangchan",
        "yl@yanliang.dev",
    }
    assert "authorization" not in seen[0].headers  # no token set: unauthenticated

    by_email = await _run(GitHubAdapter(), "yl@yanliang.dev")
    commit = next(c for c in by_email if c.value == "https://github.com/yanliangchan")
    assert commit.relation_type == "committed_as" and commit.confidence == 0.8
    assert await _run(GitHubAdapter(), "nobody-here") == []


async def test_keybase_proofs_are_proven_accounts(api):
    routes, _ = api
    routes["keybase.io/_/api/1.0/user/lookup.json"] = {
        "status": {"code": 0},
        "them": [
            {
                "basics": {"username": "yan"},
                "profile": {"full_name": "Yan Liang Chan"},
                "proofs_summary": {
                    "all": [
                        {
                            "proof_type": "twitter",
                            "nametag": "yanliangchan",
                            "service_url": "https://twitter.com/yanliangchan",
                        },
                        {"proof_type": "dns", "nametag": "yanliang.dev"},
                    ]
                },
            }
        ],
    }
    found = await _run(KeybaseAdapter(), "yan")
    x = next(c for c in found if c.value == "https://twitter.com/yanliangchan")
    assert x.attributes["verification"] == "verified" and "signed Keybase proof" in x.attributes["verification_reason"]
    assert any(c.type == "domain" and c.value == "yanliang.dev" for c in found)


async def test_gitlab_hackernews_gravatar_and_leakcheck(api):
    routes, _ = api
    routes["gitlab.com/api/v4/users/42"] = {
        "id": 42,
        "username": "yl",
        "name": "Yan",
        "twitter": "yanliangchan",
        "web_url": "https://gitlab.com/yl",
        "location": "Singapore",
    }
    routes["gitlab.com/api/v4/users"] = [{"id": 42, "username": "yl"}]
    found = await _run(GitLabAdapter(), "yl")
    assert found[0].attributes["profile"]["location"] == "Singapore" and found[1].value == "https://x.com/yanliangchan"

    routes["hacker-news.firebaseio.com/v0/user/yl.json"] = {
        "id": "yl",
        "karma": 10,
        "created": 1300000000,
        "about": 'site: <a href="https://yanliang.dev">yanliang.dev</a>',
    }
    hn = await _run(HackerNewsAdapter(), "yl")
    assert "https://yanliang.dev" in hn[0].attributes["preview"]["links"]

    routes["en.gravatar.com/"] = {
        "entry": [
            {
                "preferredUsername": "yanliangchan",
                "displayName": "Yan",
                "accounts": [{"url": "https://github.com/yanliangchan", "username": "yanliangchan", "name": "GitHub"}],
            }
        ]
    }
    grav = await _run(GravatarAdapter(), "yl@yanliang.dev")
    assert grav[0].confidence == 0.85 and {c.type for c in grav} == {"account", "username"}

    routes["leakcheck.io/api/public"] = {
        "success": True,
        "found": 1,
        "fields": ["password"],
        "sources": [{"name": "Example.com", "date": "2019-01"}],
    }
    leaks = await _run(LeakCheckAdapter(), "yl@yanliang.dev")
    assert leaks[0].type == "breach" and leaks[0].attributes["date"] == "2019-01"


async def test_rdap_and_wayback_for_domains(api):
    routes, _ = api
    routes["rdap.org/domain/yanliang.dev"] = {
        "events": [{"eventAction": "registration", "eventDate": "2020-01-02T00:00:00Z"}],
        "nameservers": [{"ldhName": "NS1.EXAMPLE.NET"}],
        "entities": [
            {"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]]},
            {"roles": ["registrant"], "vcardArray": ["vcard", [["fn", {}, "text", "REDACTED FOR PRIVACY"]]]},
        ],
    }
    found = await _run(RdapAdapter(), "yanliang.dev")
    assert found[0].attributes["rdap"]["registrar"] == "Example Registrar" and found[0].confidence == 0.0
    assert len(found) == 1  # a redacted registrant isn't a finding

    routes["web.archive.org/cdx/search/cdx"] = [
        ["timestamp", "original", "statuscode"],
        ["20190101000000", "https://yanliang.dev/about", "200"],
        ["20190101000000", "https://yanliang.dev/blog/post", "200"],
    ]
    pages = await _run(WaybackAdapter(), "yanliang.dev")
    assert [p.value for p in pages] == ["https://web.archive.org/web/20190101000000/https://yanliang.dev/about"]


async def test_keyed_tools_need_their_key_and_send_it(api, monkeypatch):
    routes, seen = api
    s = get_settings()
    assert "needs an API key (Have I Been Pwned)" in HibpAdapter().configured()
    monkeypatch.setattr(s, "hibp_key", "hibp-secret")
    routes["haveibeenpwned.com/api/v3/breachedaccount/"] = [
        {
            "Name": "Adobe",
            "Title": "Adobe",
            "BreachDate": "2013-10-04",
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
        }
    ]
    breaches = await _run(HibpAdapter(), "yl@yanliang.dev")
    assert breaches[0].value == "Adobe (HIBP)" and breaches[0].source_reliability == "A"
    assert seen[-1].headers["hibp-api-key"] == "hibp-secret"

    monkeypatch.setattr(s, "hunter_key", "hk")
    routes["api.hunter.io/v2/domain-search"] = {
        "data": {"emails": [{"value": "Jane@Acme.example", "first_name": "Jane", "last_name": "Doe", "confidence": 91}]}
    }
    hunter = await _run(HunterAdapter(), "acme.example")
    assert hunter[0].value == "jane@acme.example" and hunter[0].attributes["name"] == "Jane Doe"

    monkeypatch.setattr(s, "shodan_key", "sk")
    routes["api.shodan.io/shodan/host/8.8.8.8"] = {"ports": [53, 443], "hostnames": ["dns.google"], "org": "Google LLC"}
    shodan = await _run(ShodanAdapter(), "8.8.8.8")
    assert shodan[0].attributes["shodan"]["ports"] == [53, 443] and shodan[1].value == "dns.google"

    routes["ipinfo.io/8.8.8.8/json"] = {"ip": "8.8.8.8", "hostname": "dns.google", "org": "AS15169 Google LLC"}
    assert (await IpinfoAdapter().health_check()).ok

    monkeypatch.setattr(s, "virustotal_key", "vk")
    routes["www.virustotal.com/api/v3/domains/acme.example/subdomains"] = {"data": [{"id": "vpn.acme.example"}]}
    routes["www.virustotal.com/api/v3/domains/acme.example/resolutions"] = {
        "data": [{"attributes": {"ip_address": "203.0.113.9", "host_name": "acme.example"}}]
    }
    vt = await _run(VirusTotalAdapter(), "acme.example")
    assert {(c.type, c.value) for c in vt} == {("hostname", "vpn.acme.example"), ("ip", "203.0.113.9")}

    monkeypatch.setattr(s, "numverify_key", "nk")
    routes["apilayer.net/api/validate"] = {"valid": True, "country_name": "Singapore", "line_type": "mobile"}
    phone = await _run(NumverifyAdapter(), "+65 9123 4567")
    assert phone[0].attributes["numverify"]["line_type"] == "mobile" and phone[0].confidence == 0.0

    monkeypatch.setattr(s, "emailrep_key", "ek")
    routes["emailrep.io/"] = {
        "reputation": "high",
        "details": {"profiles": ["twitter", "github"], "first_seen": "2015"},
    }
    rep = await _run(EmailRepAdapter(), "yl@yanliang.dev")
    assert {c.value for c in rep if c.type == "registration"} == {
        "yl@yanliang.dev @ twitter",
        "yl@yanliang.dev @ github",
    }

    routes["api.shodan.io/shodan/host/1.1.1.1"] = 401
    with pytest.raises(Exception, match="API key was rejected"):
        await ShodanAdapter().run("1.1.1.1", [])


async def test_test_button_reports_each_tool(client, db, clean_secrets, api, monkeypatch):
    from app.adapters import registry

    routes, _ = api
    routes["ipinfo.io/8.8.8.8/json"] = {"ip": "8.8.8.8", "org": "AS15169 Google LLC"}
    registry.register(IpinfoAdapter())
    try:
        from app.services.tools import sync_tool_config

        await sync_tool_config(db)
        await db.commit()
        csrf = await login(client)
        page = await client.post("/integrations/ipinfo/test", data={"csrf_token": csrf})
        assert "IPinfo</strong>: working" in page.text
    finally:
        registry.unregister("ipinfo")
