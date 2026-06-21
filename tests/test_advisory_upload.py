from __future__ import annotations

import io

from app.db import SessionLocal
from app.models import Advisory
from app.seed import _minimal_pdf


def test_upload_requires_source_org(client):
    pdf = _minimal_pdf(["missing source", "CVE-2099-1000"])
    r = client.post(
        "/api/v1/advisories",
        files={"file": ("missing-source.pdf", io.BytesIO(pdf), "application/pdf")},
        data={"receive_channel": "NCST"},
    )
    assert r.status_code == 400
    assert "출처기관" in r.text


def test_upload_rejects_invalid_receive_channel(client):
    pdf = _minimal_pdf(["bad channel", "CVE-2099-1002"])
    r = client.post(
        "/api/v1/advisories",
        files={"file": ("bad-channel.pdf", io.BytesIO(pdf), "application/pdf")},
        data={"source_org": "운영기관", "receive_channel": "EMAIL"},
    )
    assert r.status_code == 400
    assert "접수채널" in r.text


def test_upload_uses_operator_metadata(client):
    pdf = _minimal_pdf(["metadata source", "CVE-2099-1001"])
    r = client.post(
        "/api/v1/advisories",
        files={"file": ("metadata-source.pdf", io.BytesIO(pdf), "application/pdf")},
        data={
            "source_org": "운영기관",
            "receive_channel": "WEBMAIL",
            "doc_no": "OPS-2026-001",
            "title": "운영 메타데이터 권고문",
            "due_at": "2026-07-31",
        },
    )
    assert r.status_code == 201
    adv_id = r.json()["id"]
    try:
        item = client.get(f"/api/v1/advisories/{adv_id}").json()
        assert item["source_org"] == "운영기관"
        assert item["receive_channel"] == "WEBMAIL"
        assert item["doc_no"] == "OPS-2026-001"
        assert item["title"] == "운영 메타데이터 권고문"
        assert item["due_at"] == "2026-07-31"
    finally:
        with SessionLocal() as db:
            adv = db.get(Advisory, adv_id)
            if adv:
                db.delete(adv)
                db.commit()
