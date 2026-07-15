"""설정 파일 API(§설정-파일 원칙) + CVE 게이트 수동 등록·자동 추출(§게이트)."""
from __future__ import annotations

import io

from app.seed import _minimal_pdf


def _upload_and_extract(client, name, lines):
    pdf = _minimal_pdf(lines)
    r = client.post("/api/v1/advisories",
                    files={"file": (name, io.BytesIO(pdf), "application/pdf")},
                    data={"source_org": "국가정보원"})
    assert r.status_code == 201, r.text
    adv = r.json()
    # 동기 검증을 위해 저장 텍스트로 직접 추출(비동기 워커 대기 없이).
    from app.core import extract
    from app.db import SessionLocal
    from app.models import Advisory, AdvisoryCve, Cve
    from app import enums
    from sqlalchemy import select
    with SessionLocal() as db:
        row = db.get(Advisory, adv["id"])
        for c in extract._regex_candidates(row.extracted_text or ""):
            cve = db.scalar(select(Cve).where(Cve.cve_id == c["cve_id_text"]))
            db.add(AdvisoryCve(
                advisory_id=row.id, cve_id_text=c["cve_id_text"],
                cve_ref_id=cve.id if cve else None,
                lookup_status=enums.LookupStatus.FOUND if cve else enums.LookupStatus.NOT_FOUND))
        row.status = enums.AdvisoryStatus.NEEDS_CVE_UPDATE
        db.commit()
    return adv


# ── 설정 파일 API ──

def test_config_list_and_roundtrip(client):
    r = client.get("/api/v1/config")
    names = {i["name"] for i in r.json()["items"]}
    assert {"source_orgs", "product_catalog", "product_aliases"} <= names

    r = client.get("/api/v1/config/source_orgs")
    assert r.status_code == 200
    value = r.json()["value"]
    assert any(o["name"] == "국가정보원" for o in value["organizations"])
    assert r.json()["path"].endswith("source_orgs.json")  # 파일이 원본(§설정-파일)

    value["organizations"].append({"name": "테스트기관", "aliases": ["TESTORG"]})
    r = client.put("/api/v1/config/source_orgs", json={"value": value})
    assert r.status_code == 200
    r = client.get("/api/v1/config/source_orgs")
    assert any(o["name"] == "테스트기관" for o in r.json()["value"]["organizations"])

    # 편집이 탐지에 즉시 반영(실시간) — 새 기관이 파일명에서 탐지된다.
    pdf = _minimal_pdf(["hello", "CVE-2099-3000"])
    up = client.post("/api/v1/advisories",
                     files={"file": ("TESTORG-2099.pdf", io.BytesIO(pdf), "application/pdf")})
    assert up.json()["source_org"] == "테스트기관"

    # 원복(다른 테스트 격리)
    value["organizations"] = [o for o in value["organizations"] if o["name"] != "테스트기관"]
    client.put("/api/v1/config/source_orgs", json={"value": value})


def test_config_validation_rejects_bad_value(client):
    r = client.put("/api/v1/config/source_orgs", json={"value": {"organizations": [{"aliases": []}]}})
    assert r.status_code == 400
    r = client.put("/api/v1/config/product_catalog",
                   json={"value": {"products": [{"key": "x", "label": "X", "patterns": ["("]}]}})
    assert r.status_code == 400          # 정규식 오류 거부
    r = client.get("/api/v1/config/unknown-name")
    assert r.status_code == 404


# ── CVE 게이트: 자동 추출 제안 + 수동 등록 ──

def test_gate_suggests_product_version_date(client):
    adv = _upload_and_extract(client, "gate-a.pdf", [
        "Security Advisory 2099.1.15",
        "Microsoft Windows 22H2 remote code execution",
        "CVE-2099-3100 affects Windows",
    ])
    r = client.get(f"/api/v1/advisories/{adv['id']}/gate")
    assert r.status_code == 200
    body = r.json()
    assert body["colors"]["cve"]                       # 색은 설정 파일 값 그대로
    item = next(i for i in body["items"] if i["cve_id"] == "CVE-2099-3100")
    sg = item["suggest"]
    assert sg["product_label"] == "Microsoft Windows"  # 필수 리스트에서 자동 매칭
    assert "22H2" in sg["versions"]
    assert sg["published_at"] == "2099-01-15"
    assert sg["source"] == "국가정보원"                 # 권고문 출처를 배포 기관 기본값으로
    windows = next(p for p in body["products"] if p["key"] == "windows")
    assert windows["color"]                            # 폼 칩 색 = PDF 하이라이트 색


def test_manual_cve_upsert_unlocks_gate(client):
    adv = _upload_and_extract(client, "gate-b.pdf", ["CVE-2099-3200 in Windows 11"])
    r = client.get(f"/api/v1/advisories/{adv['id']}/cves")
    assert r.json()["can_proceed"] is False            # 게이트 잠김

    r = client.post("/api/v1/cves", json={
        "cve_id": "CVE-2099-3200",
        "source": "국가정보원",
        "product_name": "Microsoft Windows",
        "affected_versions": ["22H2", "23H2"],
        "published_at": "2099-02-01",
    })
    assert r.status_code == 201, r.text
    out = r.json()
    assert out["created"] is True
    assert out["advisories_unlocked"] == 1
    assert out["cve"]["product_key"]                    # product_name 정규화 키 자동 부여
    assert out["cve"]["is_manual"] is True              # 수동 등록 표식(§게이트 — DB 화면 컬럼)

    r = client.get(f"/api/v1/advisories/{adv['id']}/cves")
    assert r.json()["can_proceed"] is True              # 게이트 해제
    r = client.get(f"/api/v1/advisories/{adv['id']}")
    assert r.json()["status"] == "EXTRACTED"


def test_manual_cve_upsert_all_fields_optional(client):
    adv = _upload_and_extract(client, "gate-c.pdf", ["CVE-2099-3300 details unknown"])
    # 모든 필드 빈칸 — cve_id 만으로 등록 가능(§게이트: 선택적 빈칸 허용).
    r = client.post("/api/v1/cves", json={"cve_id": "CVE-2099-3300"})
    assert r.status_code == 201, r.text
    assert r.json()["advisories_unlocked"] == 1
    r = client.post("/api/v1/cves", json={"cve_id": "not-a-cve"})
    assert r.status_code == 400


def test_pdf_view_highlights_carry_category_colors(client):
    adv = _upload_and_extract(client, "gate-d.pdf", [
        "Microsoft Windows 22H2", "CVE-2099-3400",
    ])
    r = client.get(f"/api/v1/advisories/{adv['id']}/pdf-view")
    assert r.status_code == 200
    body = r.json()
    assert any(l["category"] == "cve" for l in body["legend"])
    if body.get("available"):
        cats = {(b.get("category"), b.get("color")) for b in body["boxes"]}
        cfg = client.get("/api/v1/config/product_catalog").json()["value"]
        windows_color = next(p["color"] for p in cfg["products"] if p["key"] == "windows")
        assert ("cve", cfg["colors"]["cve"]) in cats
        assert ("product", windows_color) in cats       # PDF 영역 색 = 카탈로그 색 항상 동일
