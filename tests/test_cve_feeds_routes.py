"""CVE 피드 업로드·적용 라우트 통합 테스트 (스트리밍 + 벌크 upsert)."""
from __future__ import annotations

import gzip
import json

from sqlalchemy import func, select


def _nvd_bytes(ids, *, sev="CRITICAL", score=9.8) -> bytes:
    doc = {"version": "2.0", "vulnerabilities": [
        {"cve": {"id": i, "published": "2099-03-04T12:00:00",
                 "descriptions": [{"lang": "en", "value": f"desc, with }} ] tricky {i}"}],
                 "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score},
                                                "baseSeverity": sev}]}}}
        for i in ids]}
    return json.dumps(doc, ensure_ascii=False).encode("utf-8")


def _ids(start, n):
    return [f"CVE-2099-{i:05d}" for i in range(start, start + n)]


def _upload(client, data: bytes, name="nvd.json"):
    return client.post("/api/v1/cve-feeds",
                       files={"file": (name, data, "application/octet-stream")},
                       data={"source": "NVD"})


def _cve_count(like="CVE-2099-%"):
    from app.db import SessionLocal
    from app.models import Cve
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(Cve).where(Cve.cve_id.like(like)))


def test_upload_validate_apply_idempotent(client):
    n = 2300  # > 검증 IN 청크(900) & 적용 배치(1000) → 다중 배치
    r = _upload(client, _nvd_bytes(_ids(0, n)))
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["added_count"], body["updated_count"]) == (n, 0)
    assert body["status"] == "VALIDATED"
    imp_id = body["import_id"]

    # staged_payload 미사용 + 원본 파일 저장 확인
    from app.db import SessionLocal
    from app.models import CveFeedImport
    with SessionLocal() as db:
        imp = db.get(CveFeedImport, imp_id)
        assert imp.staged_payload is None
        assert imp.file_path

    r2 = client.post(f"/api/v1/cve-feeds/{imp_id}/apply")
    assert r2.status_code == 200, r2.text
    assert r2.json()["added_count"] == n
    assert _cve_count() == n

    with SessionLocal() as db:
        imp = db.get(CveFeedImport, imp_id)
        assert imp.status.value == "APPLIED"
        assert imp.applied_at is not None

    # 같은 import 재적용 → 409
    assert client.post(f"/api/v1/cve-feeds/{imp_id}/apply").status_code == 409


def test_overlapping_import_counts(client):
    n = 1500
    a = _upload(client, _nvd_bytes(_ids(0, n))).json()
    client.post(f"/api/v1/cve-feeds/{a['import_id']}/apply")

    # 500..1999: 500 신규(1500..1999) + 1000 갱신(500..1499)
    r = _upload(client, _nvd_bytes(_ids(500, n)))
    b = r.json()
    assert (b["added_count"], b["updated_count"]) == (500, 1000), b
    applied = client.post(f"/api/v1/cve-feeds/{b['import_id']}/apply").json()
    assert (applied["added_count"], applied["updated_count"]) == (500, 1000)
    assert _cve_count() == 2000  # 0..1999


def test_bulk_upsert_updates_fields(client):
    ids = _ids(0, 10)
    a = _upload(client, _nvd_bytes(ids, sev="LOW", score=2.0)).json()
    client.post(f"/api/v1/cve-feeds/{a['import_id']}/apply")

    from app import enums
    from app.db import SessionLocal
    from app.models import Cve
    with SessionLocal() as db:
        c = db.scalar(select(Cve).where(Cve.cve_id == ids[0]))
        assert c.severity == enums.Severity.LOW and float(c.cvss_score) == 2.0
        assert c.updated_at is None  # 신규행

    # 재적재: 값 변경 → on_conflict UPDATE
    b = _upload(client, _nvd_bytes(ids, sev="CRITICAL", score=9.9)).json()
    client.post(f"/api/v1/cve-feeds/{b['import_id']}/apply")
    with SessionLocal() as db:
        c = db.scalar(select(Cve).where(Cve.cve_id == ids[0]))
        assert c.severity == enums.Severity.CRITICAL and float(c.cvss_score) == 9.9
        assert c.updated_at is not None  # 갱신됨
    assert _cve_count() == 10  # 중복 없음


def test_gzip_upload_end_to_end(client):
    ids = _ids(0, 25)
    gz = gzip.compress(_nvd_bytes(ids))
    r = _upload(client, gz, name="nvd.json.gz")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["added_count"] == 25
    assert client.post(f"/api/v1/cve-feeds/{body['import_id']}/apply").json()["added_count"] == 25
    assert _cve_count() == 25


def test_empty_feed_rejected(client):
    r = _upload(client, b'{"vulnerabilities": []}')
    assert r.status_code == 400


def test_garbage_feed_rejected(client):
    r = _upload(client, b'{"unknown": 123}')
    assert r.status_code == 400
