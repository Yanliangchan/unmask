"""Importing STIX and UNMASK exports: validated, reported, marked imported, never observed."""

import json
import re
import uuid

from sqlalchemy import select

from app import jobs
from app.models import AccessLog, Entity, Relation, ScanRun
from app.services import importer
from tests.conftest import case_form_data, login

STIX = {
    "type": "bundle", "id": "bundle--1",
    "objects": [
        {"type": "email-addr", "id": "email-addr--a", "value": "Jane@Corp.example", "spec_version": "2.1"},
        {"type": "email-addr", "id": "email-addr--dup", "value": "jane@corp.example"},
        {"type": "domain-name", "id": "domain-name--b", "value": "corp.example", "resolves_to_refs": []},
        {"type": "ipv4-addr", "id": "ipv4-addr--c", "value": "not-an-ip"},
        {"type": "user-account", "id": "user-account--d", "account_login": "jdoe", "account_type": "forum.example",
         "x_unmask_profile_url": "https://forum.example/u/jdoe", "is_privileged": False},
        {"type": "user-account", "id": "user-account--e", "account_login": "jdoe_alt"},
        {"type": "identity", "id": "identity--f", "name": "Jane Doe", "identity_class": "individual"},
        {"type": "identity", "id": "identity--g", "name": "Acme Corp", "identity_class": "organization"},
        {"type": "indicator", "id": "indicator--h", "pattern": "[x]"},
        {"type": "malware", "id": "malware--i", "name": "x"},
        {"type": "relationship", "id": "relationship--j", "relationship_type": "related-to",
         "source_ref": "email-addr--dup", "target_ref": "domain-name--b"},
        {"type": "relationship", "id": "relationship--k", "relationship_type": "related-to",
         "source_ref": "email-addr--a", "target_ref": "indicator--h"},
        {"type": "grouping", "id": "grouping--l", "context": "x", "object_refs": []},
    ],
}  # fmt: skip


def test_check_validates_and_reports_everything_it_does_not_take():
    plan = importer.check(json.dumps(STIX).encode(), "intel.json")
    assert plan.format == "STIX 2.1 bundle"
    assert {(i.type, i.value) for i in plan.items} == {
        ("email", "jane@corp.example"), ("domain", "corp.example"), ("account", "https://forum.example/u/jdoe"),
        ("username", "jdoe_alt"), ("name", "Jane Doe")}  # fmt: skip
    assert plan.duplicates == 1
    assert len(plan.links) == 1 and plan.dropped_links == 1  # the dup's link survives via its alias
    assert plan.unsupported_objects == {"indicator": 1, "malware": 1}
    assert plan.ignored_fields == {"user-account": ["is_privileged"]}
    reasons = {x["ref"]: x["reason"] for x in plan.invalid}
    assert reasons == {"ipv4-addr--c": "not an IP address", "identity--g": "identity is not an individual"}
    assert importer.Plan.unseal(plan.seal()) == plan


def test_check_refuses_what_it_cannot_read():
    import pytest

    cases = [(b"not json", "not valid JSON"), (b"[]", "expected a JSON object"),
             (b'{"type": "report"}', "not a STIX 2.1 bundle"), (b'{"type": "bundle"}', "'objects' list")]  # fmt: skip
    for raw, why in cases:
        with pytest.raises(importer.ImportError_, match=re.escape(why)):
            importer.check(raw, "x.json")


def test_unmask_exports_bring_values_but_not_judgements():
    data = {"format": "unmask-case-export", "findings": [
        {"id": "1", "type": "email", "value": "a@b.example", "confidence": 0.99, "decision": "confirmed"},
        {"id": "2", "type": "hostname", "value": "www.b.example", "attributes": {"url": "javascript:alert(1)"}},
        {"id": "3", "type": "breach", "value": "x"}],
        "links": [{"from": "1", "to": "2", "type": "email_at_domain"}]}  # fmt: skip
    plan = importer.check(json.dumps(data).encode(), "case.json")
    assert [(i.type, i.value, i.url) for i in plan.items] == [("email", "a@b.example", None),
                                                               ("domain", "www.b.example", None)]  # fmt: skip
    assert plan.ignored_fields == {"finding": ["confidence", "decision"]}
    assert plan.invalid == [{"ref": "3", "type": "breach", "reason": "type breach can't be imported"}]


async def test_import_is_checked_then_committed_as_imported_never_observed(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"Imp {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()

    files = {"file": ("intel.json", json.dumps(STIX).encode(), "application/json")}
    page = await client.post(f"/cases/{case_id}/import/check", data={"csrf_token": csrf}, files=files)
    assert page.status_code == 200 and "Import 5 findings" in page.text
    assert "indicator" in page.text and "is_privileged" in page.text and "not an IP address" in page.text
    assert await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.source_tool == "import")) is None

    token = re.search(r'name="token" value="([^"]+)"', page.text).group(1)
    tampered = await client.post(f"/cases/{case_id}/import/commit", data={"csrf_token": csrf, "token": token[:-4]})
    assert tampered.status_code == 400

    done = await client.post(f"/cases/{case_id}/import/commit", data={"csrf_token": csrf, "token": token})
    assert done.status_code == 303 and "tool=import" in done.headers["location"]
    db.expire_all()
    imported = (await db.scalars(select(Entity).where(Entity.case_id == case_id, Entity.source_tool == "import"))).all()
    assert len(imported) == 5
    assert all(e.source_reliability == "F" and e.confidence <= 0.3 and e.verification is None for e in imported)
    assert all(e.attributes["origin"] == "imported" and e.attributes["imported_from"] == "intel.json" for e in imported)
    rels = (await db.scalars(select(Relation).where(Relation.case_id == case_id, Relation.basis == "imported"))).all()
    assert len(rels) == 1 and rels[0].relation_type == "imported_link"
    seed = await db.scalar(select(Entity).where(Entity.case_id == case_id, Entity.is_seed))
    assert not any(r.entity_a_id == seed.id for r in rels)  # never hung off the target
    run = await db.scalar(select(ScanRun).where(ScanRun.case_id == case_id, ScanRun.triggered_by == "import"))
    assert run.status == "completed" and run.failure_details["_import"]["findings"] == 5
    log = await db.scalar(select(AccessLog).where(AccessLog.case_id == case_id, AccessLog.action == "import_findings"))
    assert log.detail["findings"] == 5 and log.detail["invalid"] == 2

    table = (await client.get(f"/cases/{case_id}/entities", params={"show": "all", "tool": "import"})).text
    assert "Imported · not observed" in table and "jane@corp.example" in table


async def test_bad_files_get_a_reason_and_samples_refuse_imports(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"Imp {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    files = {"file": ("x.json", b"{nope", "application/json")}
    page = await client.post(f"/cases/{case_id}/import/check", data={"csrf_token": csrf}, files=files)
    assert page.status_code == 422 and "not valid JSON" in page.text
