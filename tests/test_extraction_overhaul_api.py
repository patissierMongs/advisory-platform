"""§개편 API 테스트 — CVE 수정/소프트삭제/복원, 영향 제품 CRUD·재추출·CVE 적용,
출처기관 일괄 지정, 발송이력 자산 단위 집계."""
from __future__ import annotations

import io

import pytest
from sqlalchemy import delete

from app import enums
from app.db import SessionLocal
from app.models import (
    Advisory, AdvisoryCve, AdvisoryProduct, Asset, Cve, Department, Match, Notification,
)
from app.seed import _minimal_pdf


def _upload(client, lines, **data):
    pdf = _minimal_pdf(lines)
    r = client.post(
        "/api/v1/advisories",
        files={"file": (f"t-{abs(hash(tuple(lines)))}.pdf", io.BytesIO(pdf), "application/pdf")},
        data=data,
    )
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    # _minimal_pdf 는 ASCII 전용(한글 소실) — 실제 권고문처럼 한글 본문을 직접 주입.
    with SessionLocal() as db:
        adv = db.get(Advisory, aid)
        adv.extracted_text = "\n".join(lines)
        db.commit()
    return aid


@pytest.fixture()
def cleanup():
    ids: dict[str, list[int]] = {"advisory": []}
    yield ids
    with SessionLocal() as db:
        for aid in ids["advisory"]:
            db.execute(delete(Match).where(Match.advisory_id == aid))
            db.execute(delete(Notification).where(Notification.advisory_id == aid))
            db.execute(delete(AdvisoryProduct).where(AdvisoryProduct.advisory_id == aid))
            db.execute(delete(AdvisoryCve).where(AdvisoryCve.advisory_id == aid))
            db.execute(delete(Advisory).where(Advisory.id == aid))
        db.commit()


# ── 추출 CVE: 수정·소프트삭제·복원 ───────────────────────────────────────────

def test_cve_soft_delete_restore_and_edit(client, cleanup):
    aid = _upload(client, ["CVE-2099-1111 취약점", "CVE-2099-2222 동반"], source_org="테스트원")
    cleanup["advisory"].append(aid)
    # 동기 추출을 흉내내기 위해 수동 추가 사용(업로드만으로 advisory_cve 는 비어 있음).
    r = client.post(f"/api/v1/advisories/{aid}/cves", json={"cve_id": "CVE-2099-1111"})
    assert r.status_code == 201
    ac_id = r.json()["id"]

    # 소프트 삭제 → 목록에서 빠지고 deleted 에 남는다.
    r = client.delete(f"/api/v1/advisory-cves/{ac_id}")
    assert r.status_code == 200 and r.json()["restorable"] is True
    body = client.get(f"/api/v1/advisories/{aid}/cves").json()
    assert body["summary"]["extracted"] == 0
    assert body["summary"]["deleted"] == 1
    assert body["deleted"][0]["cve_id_text"] == "CVE-2099-1111"

    # 복원 → 다시 활성.
    r = client.post(f"/api/v1/advisory-cves/{ac_id}/restore")
    assert r.status_code == 200
    body = client.get(f"/api/v1/advisories/{aid}/cves").json()
    assert body["summary"]["extracted"] == 1 and body["summary"]["deleted"] == 0

    # 그 자리에서 코드 수정.
    r = client.patch(f"/api/v1/advisory-cves/{ac_id}", json={"cve_id": "CVE 2099 3333"})
    assert r.status_code == 200
    assert r.json()["cve_id_text"] == "CVE-2099-3333"

    # 동일 코드 재추가 시 409, 삭제 후 재추가는 복원으로 동작.
    client.post(f"/api/v1/advisories/{aid}/cves", json={"cve_id": "CVE-2099-3333"}).status_code
    r = client.post(f"/api/v1/advisories/{aid}/cves", json={"cve_id": "CVE-2099-3333"})
    assert r.status_code == 409
    client.delete(f"/api/v1/advisory-cves/{ac_id}")
    r = client.post(f"/api/v1/advisories/{aid}/cves", json={"cve_id": "CVE-2099-3333"})
    assert r.status_code == 201   # 소프트 삭제분 복원


# ── 영향 제품: 수동 추가·수정·삭제·복원·재추출 ───────────────────────────────

def test_product_crud_and_manual_reextract(client, cleanup):
    aid = _upload(client, ["Apache Tomcat 9.0.30 이하 버전 취약점", "CVE-2099-4444"],
                  source_org="테스트원")
    cleanup["advisory"].append(aid)

    # 수동 추가 + 그 자리 수정.
    r = client.post(f"/api/v1/advisories/{aid}/products",
                    json={"product_name": "GitLab CE", "affected_versions": {"lte": "16.11.1"}})
    assert r.status_code == 201
    pid = r.json()["id"]
    r = client.patch(f"/api/v1/advisory-products/{pid}",
                     json={"affected_versions": {"lt": "17.0"}, "fixed_version": "17.0"})
    assert r.status_code == 200
    assert r.json()["affected_versions"] == {"lt": "17.0"}

    # 소프트 삭제 → 복원.
    assert client.delete(f"/api/v1/advisory-products/{pid}").json()["restorable"] is True
    body = client.get(f"/api/v1/advisories/{aid}/products").json()
    assert body["summary"]["deleted"] == 1
    assert client.post(f"/api/v1/advisory-products/{pid}/restore").status_code == 200

    # 수동 재추출 — 본문에서 Tomcat 규칙이 제안된다(삭제했던 추출 제안도 복귀 대상).
    r = client.post(f"/api/v1/advisories/{aid}/products/reextract")
    assert r.status_code == 200
    keys = {p["product_key"]: p for p in r.json()["items"]}
    assert keys["apache_tomcat"]["affected_versions"] == {"lte": "9.0.30"}


def test_apply_product_to_cve_unblocks_gate(client, cleanup):
    aid = _upload(client, ["nginx 1.24.0 미만 취약점"], source_org="테스트원")
    cleanup["advisory"].append(aid)
    r = client.post(f"/api/v1/advisories/{aid}/cves", json={"cve_id": "CVE-2099-5555"})
    ac = r.json()
    assert ac["lookup_status"] == "NOT_FOUND"

    client.post(f"/api/v1/advisories/{aid}/products/reextract")
    prods = client.get(f"/api/v1/advisories/{aid}/products").json()["items"]
    pid = next(p["id"] for p in prods if p["product_key"] == "nginx")

    r = client.post(f"/api/v1/advisory-products/{pid}/apply-to-cve",
                    json={"cve_id": "CVE-2099-5555"})
    assert r.status_code == 200, r.text
    body = client.get(f"/api/v1/advisories/{aid}/cves").json()
    assert body["items"][0]["lookup_status"] == "FOUND"
    assert body["can_proceed"] is True
    with SessionLocal() as db:
        cve = db.query(Cve).filter_by(cve_id="CVE-2099-5555").one()
        assert cve.product_key == "nginx"
        assert cve.affected_versions == {"lt": "1.24.0"}
        # FK 해제 후 삭제(advisory_cve.cve_ref_id → cve.id)
        for row in db.query(AdvisoryCve).filter_by(cve_ref_id=cve.id).all():
            row.cve_ref_id = None
        db.flush()
        db.delete(cve)
        db.commit()


# ── 출처기관 일괄 지정 ───────────────────────────────────────────────────────

def test_bulk_source_only_empty(client, cleanup):
    a1 = _upload(client, ["빈 출처 권고문 CVE-2099-6666"])
    a2 = _upload(client, ["출처 있는 권고문 CVE-2099-7777"], source_org="국정원")
    cleanup["advisory"] += [a1, a2]

    r = client.post("/api/v1/advisories/source-org",
                    json={"ids": [a1, a2], "source_org": "국토부", "only_empty": True})
    assert r.status_code == 200
    assert r.json() == {"updated": 1, "skipped": 1, "source_org": "국토부"}
    assert client.get(f"/api/v1/advisories/{a1}").json()["source_org"] == "국토부"
    assert client.get(f"/api/v1/advisories/{a2}").json()["source_org"] == "국정원"


# ── 발송이력: 개별 대상(자산) 단위 집계 + 회신 취소 ──────────────────────────

def test_history_asset_level_counts_and_ack_cancel(client, cleanup):
    with SessionLocal() as db:
        dept = Department(name="개편테스트부서")
        db.add(dept)
        db.flush()
        adv = Advisory(doc_no="OVH-1", title="자산단위 집계", status=enums.AdvisoryStatus.NOTIFYING)
        db.add(adv)
        db.flush()
        ac = AdvisoryCve(advisory_id=adv.id, cve_id_text="CVE-2099-8888",
                         lookup_status=enums.LookupStatus.NOT_FOUND)
        db.add(ac)
        a1 = Asset(asset_no="OVH-A1", department_id=dept.id, product_key="nginx")
        a2 = Asset(asset_no="OVH-A2", department_id=dept.id, product_key="nginx")
        db.add_all([a1, a2])
        db.flush()
        m1 = Match(advisory_id=adv.id, advisory_cve_id=ac.id, asset_id=a1.id,
                   ack_status=enums.AckStatus.DONE)
        m2 = Match(advisory_id=adv.id, advisory_cve_id=ac.id, asset_id=a2.id)
        db.add_all([m1, m2])
        n = Notification(advisory_id=adv.id, department_id=dept.id,
                         asset_ids=[a1.id, a2.id],
                         status=enums.NotificationStatus.SENT,
                         ack_status=enums.AckStatus.DONE)
        db.add(n)
        db.commit()
        aid, nid, dept_id = adv.id, n.id, dept.id
    cleanup["advisory"].append(aid)

    item = next(i for i in client.get("/api/v1/history/advisories").json()["items"]
                if i["id"] == aid)
    # 권고문 전체: 자산 2대 중 1대 완료 = 50%
    assert item["asset_total"] == 2 and item["asset_done"] == 1
    assert item["asset_done_rate"] == 50
    d = item["departments"][0]
    assert d["asset_ack"]["total"] == 2 and d["asset_ack"]["done"] == 1
    assert d["asset_ack"]["done_rate"] == 50

    # 실수로 누른 '조치 회신' 취소 — NONE 으로 되돌리면 부서·자산 모두 초기화.
    r = client.patch(f"/api/v1/notifications/{nid}/ack", json={"ack_status": "NONE"})
    assert r.status_code == 200
    assert r.json()["ack_status"] == "NONE"
    with SessionLocal() as db:
        rows = db.query(Match).filter_by(advisory_id=aid).all()
        assert all(m.ack_status == enums.AckStatus.NONE for m in rows)
        n = db.get(Notification, nid)
        assert n.status == enums.NotificationStatus.SENT   # ACKED 해제
        # FK 순서: match/notification → asset → department
        db.execute(delete(Match).where(Match.advisory_id == aid))
        db.execute(delete(Notification).where(Notification.advisory_id == aid))
        db.execute(delete(Asset).where(Asset.asset_no.in_(["OVH-A1", "OVH-A2"])))
        db.execute(delete(Department).where(Department.id == dept_id))
        db.commit()
