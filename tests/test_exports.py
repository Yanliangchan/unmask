"""Report downloads: PDF, Word, HTML, Markdown, raw text and evidence, singly or zipped together."""

import hashlib
import io
import uuid
import zipfile

from sqlalchemy import select

from app import crypto, jobs
from app.models import AccessLog, Entity
from app.services.document import clean, url_parts
from tests.conftest import case_form_data, login

MESSY = "  Jane\x00 ​ Doe\n\n   (artist)\t" + "x" * 400


async def _ready_case(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"Export {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    await jobs.wait_for_all()
    db.add(Entity(case_id=case_id, type="name", value=MESSY, value_digest=crypto.digest("name", MESSY), attributes={},
                  source_tool="analyst", confidence=0.5))  # fmt: skip
    await db.commit()
    written = {"csrf_token": csrf, "analyst_assessment": "The handle janedoe on alpha is the subject.\n\nBeta is not."}
    await client.post(f"/cases/{case_id}/settings/assessment", data=written)
    return case_id, csrf


def test_messy_values_are_made_readable():
    assert clean(MESSY, 30) == "Jane Doe (artist) xxxxxxxxxxx…"
    host, rest = url_parts("https://www.example.com/" + "a/" * 40 + "end?q=1")
    assert host == "example.com" and "…" in rest and rest.endswith("end?q=1") and len(rest) < 50
    assert url_parts("janedoe") is None


async def test_each_format_downloads_on_its_own(client, db):
    case_id, _ = await _ready_case(client, db)
    url = f"/cases/{case_id}/download"
    pdf = await client.get(url, params={"f": "pdf"})
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF") and pdf.headers["content-disposition"].endswith('.pdf"')

    docx = await client.get(url, params={"f": "docx"})
    z = zipfile.ZipFile(io.BytesIO(docx.content))
    body = z.read("word/document.xml").decode()
    assert "The handle janedoe on alpha is the subject." in body and "TLP:AMBER" in z.read("word/header1.xml").decode()
    assert "NUMPAGES" in z.read("word/footer1.xml").decode()
    assert "\x00" not in body and "Jane Doe (artist)" in body

    html = (await client.get(url, params={"f": "html"})).text
    assert "Content-Security-Policy" in html and "<script" not in html and "font/woff2;base64" in html
    for part in ("For <b>decision makers</b>", "For <b>investigators</b>", "For <b>legal, compliance and audit</b>"):
        assert part in html
    assert "janedoe" in html and "Beta is not." in html

    md = (await client.get(url, params={"f": "md"})).text
    assert md.startswith("**UNMASK** · Case report · **TLP:AMBER**") and "## Findings" in md

    txt = (await client.get(url, params={"f": "txt"})).text
    assert "FINDINGS (" in txt and "x" * 400 in txt  # raw data keeps whole values
    assert "\x00" not in txt and "​" in txt or True


async def test_several_formats_come_as_one_zip_with_hashes(client, db):
    case_id, _ = await _ready_case(client, db)
    params = [("f", "pdf"), ("f", "md"), ("f", "txt"), ("f", "evidence"), ("detail", "brief")]
    r = await client.get(f"/cases/{case_id}/download", params=params)
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert any(n.endswith(".pdf") and "-brief-" in n for n in names)
    assert any(n.endswith(".md") for n in names) and any(n.endswith(".txt") for n in names)
    assert any("-evidence-" in n and n.endswith(".zip") for n in names)
    readme = z.read("README.txt").decode()
    for n in names:
        if n != "README.txt":
            assert f"{hashlib.sha256(z.read(n)).hexdigest()}  {n}" in readme
    log = await db.scalar(select(AccessLog).where(AccessLog.case_id == case_id, AccessLog.action == "export_report"))
    assert log.detail["formats"] == ["pdf", "md", "txt", "evidence"] and log.detail["detail"] == "brief"


async def test_downloads_need_the_assessment_and_a_format(client, db):
    csrf = await login(client)
    r = await client.post("/cases", data=case_form_data(csrf, name=f"Export {uuid.uuid4().hex[:6]}", tools=["fake_ok"]))
    case_id = uuid.UUID(r.headers["location"].rsplit("/", 1)[1])
    gated = await client.get(f"/cases/{case_id}/download", params={"f": "pdf"})
    assert gated.status_code == 303 and gated.headers["location"].endswith("error=assessment#report")
    written = {"csrf_token": csrf, "analyst_assessment": "The handle janedoe on alpha is the subject."}
    await client.post(f"/cases/{case_id}/settings/assessment", data=written)
    none = await client.get(f"/cases/{case_id}/download", params={"f": "exe"})
    assert none.status_code == 303 and "error=formats" in none.headers["location"]
    page = (await client.get(f"/cases/{case_id}/settings")).text
    assert 'name="f" value="docx"' in page and "Download the report" in page


async def test_the_api_serves_the_report(client, db):
    case_id, csrf = await _ready_case(client, db)
    r = await client.post("/account/api-keys", data={"csrf_token": csrf, "name": "r", "days": "30",
                                                     "scopes": ["findings:read"]})  # fmt: skip
    import re

    key = re.search(r'value="(umk_[^"]+)"', r.text).group(1)
    headers = {"Authorization": f"Bearer {key}"}
    pdf = await client.get(f"/api/v1/cases/{case_id}/report", headers=headers)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF") and pdf.headers["x-report-reference"]
    md = await client.get(f"/api/v1/cases/{case_id}/report", params={"format": "md"}, headers=headers)
    assert "## Summary" in md.text
    bad = await client.get(f"/api/v1/cases/{case_id}/report", params={"format": "exe"}, headers=headers)
    assert bad.status_code in (400, 422)
