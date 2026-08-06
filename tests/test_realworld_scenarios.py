"""실사용 시나리오 회귀 테스트 — 코드추적·라이브 시뮬레이션에서 확증된 결함들의 고정.

시나리오 그룹: A(권고문 수명주기) · B(매칭·발송) · C(게시판 회신 정합) · D(자산·CVE 운영).
"""
from __future__ import annotations

import io

import pytest
from conftest import signed_webhook_post
from openpyxl import Workbook

from app.db import SessionLocal
from app.models import (
    Advisory, AdvisoryComment, AdvisoryCve, Asset, Cve, Department, ExclusionRule, Match,
    Notification,
)

_TEST_DEPTS = ("회귀검증부", "중복검증부")


@pytest.fixture(autouse=True)
def _cleanup_scenario_state():
    """각 테스트 뒤 이 모듈이 만든 상태 정리 — FK 순서 준수(자식→부모).

    conftest 의 _clean_tables 는 cve 테이블만 비우므로, advisory_cve.cve_ref_id 가
    남아 있으면 다음 테스트 셋업에서 FK 위반이 난다.
    """
    yield
    from sqlalchemy import delete

    with SessionLocal() as db:
        db.execute(delete(Match))
        db.execute(delete(ExclusionRule))
        db.execute(delete(Notification))
        db.execute(delete(AdvisoryComment))
        db.execute(delete(AdvisoryCve))
        db.execute(delete(Advisory))
        db.execute(delete(Asset))
        for name in _TEST_DEPTS:
            db.execute(delete(Department).where(Department.name == name))
        db.commit()


def _mkpdf(lines):
    from app.seed import _minimal_pdf
    return _minimal_pdf(lines)


def _upload(client, lines, **form):
    form.setdefault("source_org", "국가정보원")
    r = client.post("/api/v1/advisories",
                    files={"file": (f"t-{abs(hash(tuple(lines)))}.pdf", io.BytesIO(_mkpdf(lines)), "application/pdf")},
                    data=form)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _extract_sync(client, aid):
    client.post(f"/api/v1/advisories/{aid}/extract")
    import time
    for _ in range(60):
        adv = client.get(f"/api/v1/advisories/{aid}").json()
        if adv.get("extract_phase") in ("done", "failed"):
            return adv
        time.sleep(0.1)
    return adv


def _seed_cve(cve_id="CVE-2077-1000", product_key="windows_11", versions=None):
    with SessionLocal() as db:
        db.add(Cve(cve_id=cve_id, product_name="Windows 11", product_key=product_key,
                   affected_versions=versions or ["23H2"], source="TEST"))
        db.commit()


def _seed_dept_assets(dept_name="회귀검증부", assets=(("RW-0001", "23H2"), ("RW-0002", "23H2"))):
    with SessionLocal() as db:
        dept = Department(name=dept_name)
        db.add(dept)
        db.flush()
        for no, ver in assets:
            db.add(Asset(asset_no=no, department_id=dept.id, product_key="windows_11",
                         product_raw="Windows 11", version_raw=ver, version_norm=ver))
        db.commit()
        return dept.id


@pytest.fixture()
def matched_advisory(client):
    """CVE 1건 + 부서 1개(자산 2대) 매칭까지 끝난 권고문."""
    _seed_cve()
    dept_id = _seed_dept_assets()
    aid = _upload(client, ["regression base", "CVE-2077-1000"])
    _extract_sync(client, aid)
    r = client.post(f"/api/v1/advisories/{aid}/match")
    assert r.status_code == 200, r.text
    return {"aid": aid, "dept_id": dept_id}


# ── B7: 조치기한 없는 권고문의 HTML 보고서 (라이브 재현: 500) ──
def test_report_html_without_due_date(client):
    aid = _upload(client, ["no due date advisory"])
    r = client.get(f"/api/v1/advisories/{aid}/report.html")
    assert r.status_code == 200, r.text[:200]


# ── A5b: 수동 CVE 변형 입력 정규화 (라이브 재현: 'CVE_2026_21360' 그대로 저장 → 영구 NOT_FOUND) ──
def test_manual_cve_add_normalizes_variants(client):
    _seed_cve("CVE-2077-2000")
    aid = _upload(client, ["manual add target"])
    r = client.post(f"/api/v1/advisories/{aid}/cves", json={"cve_id": "CVE_2077_2000"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["cve_id_text"] == "CVE-2077-2000"      # 표준형 정규화
    assert body["lookup_status"] == "FOUND"            # DB 표준형과 즉시 일치


# ── A3: CVE 0건 공지형 — 게이트 통과(0건 매칭) + 수동 종결 ──
def test_notice_without_cves_can_match_and_close(client):
    aid = _upload(client, ["general security notice, no cve ids"])
    _extract_sync(client, aid)
    r = client.post(f"/api/v1/advisories/{aid}/match")
    assert r.status_code == 200, r.text                 # 공집합은 '미등록 CVE' 아님 → 통과
    assert r.json()["matched"] == 0
    # 발송은 여전히 차단(활성 매칭 없음)
    r = client.post(f"/api/v1/advisories/{aid}/notifications", json={"all": True, "channels": ["MAIL"]})
    assert r.status_code == 409
    # 수동 종결로 마감
    r = client.post(f"/api/v1/advisories/{aid}/close", json={"reason": "공지형 — 대상 자산 없음"})
    assert r.status_code == 200 and r.json()["status"] == "COMPLETED"
    # 멱등
    assert client.post(f"/api/v1/advisories/{aid}/close").json().get("already_closed") is True


# ── A2: 텍스트 없는(스캔본) PDF — 조용한 완료 대신 failed + 수동 CVE 보존 ──
def test_scan_pdf_marks_failed_and_preserves_manual_cves(client):
    scan = (b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
            b"trailer<</Size 4/Root 1 0 R>>\n%%EOF")
    r = client.post("/api/v1/advisories",
                    files={"file": ("scan.pdf", io.BytesIO(scan), "application/pdf")},
                    data={"source_org": "국가정보원"})
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    adv = _extract_sync(client, aid)
    assert adv["extract_phase"] == "failed"
    assert "텍스트" in (adv.get("error_message") or "")
    # 수동 보정 → 재추출해도 수동분 보존
    _seed_cve("CVE-2077-3000")
    r = client.post(f"/api/v1/advisories/{aid}/cves", json={"cve_id": "CVE-2077-3000"})
    assert r.status_code == 201
    adv = _extract_sync(client, aid)                    # 재시도(여전히 텍스트 없음 → failed)
    codes = [c["cve_id_text"] for c in client.get(f"/api/v1/advisories/{aid}/cves").json()["items"]]
    assert codes == ["CVE-2077-3000"]                   # 수동 추가분이 사라지지 않음


# ── B3b: 오탐 제외 후 재발송 — 부서당 Notification 1행 유지 (라이브 재현: 2행 누적) ──
def test_resend_after_exclusion_keeps_single_department_row(client, matched_advisory):
    aid, dept_id = matched_advisory["aid"], matched_advisory["dept_id"]
    r = client.post(f"/api/v1/advisories/{aid}/notifications",
                    json={"departments": [{"department_id": dept_id, "channels": ["MAIL"]}]})
    assert r.status_code == 200, r.text
    # 자산 1대 오탐 제외 → 구성이 바뀐 재발송
    m = client.get(f"/api/v1/advisories/{aid}/matches").json()["items"][0]
    assert client.patch(f"/api/v1/matches/{m['id']}", json={"status": "EXCLUDED", "reason": "오탐"}).status_code == 200
    r = client.post(f"/api/v1/advisories/{aid}/notifications",
                    json={"departments": [{"department_id": dept_id, "channels": ["MAIL"]}]})
    assert r.status_code == 200, r.text

    with SessionLocal() as db:
        rows = db.query(Notification).filter(Notification.advisory_id == aid,
                                             Notification.department_id == dept_id).all()
        assert len(rows) == 1, [r_.idempotency_key for r_ in rows]
        assert len(rows[0].asset_ids) == 1              # 제외분이 빠진 최신 구성
    hist = client.get("/api/v1/history/advisories").json()["items"]
    dept_rows = [d for it in hist if it["id"] == aid for d in it["departments"]]
    assert len(dept_rows) == 1                          # 롤업도 부서당 1행


# ── C2b/C3: 자산 미지정 회신 = 부서 전체 선언, 정정 시 종결 해제 ──
def test_comment_without_match_ids_is_department_wide(client, matched_advisory):
    aid, dept_id = matched_advisory["aid"], matched_advisory["dept_id"]
    client.post(f"/api/v1/advisories/{aid}/notifications",
                json={"departments": [{"department_id": dept_id, "channels": ["MAIL"]}]})
    client.post(f"/api/v1/advisories/{aid}/board")
    # 자산 미체크 DONE → 부서 매칭 전체 DONE + notification ACKED
    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"department_id": dept_id, "author_name": "담당자", "body": "전부 완료",
                          "ack_status": "DONE"})
    assert r.status_code == 201, r.text
    with SessionLocal() as db:
        acks = [m.ack_status.value for m in db.query(Match).filter(Match.advisory_id == aid)]
        assert set(acks) == {"DONE"}
        n = db.query(Notification).filter(Notification.advisory_id == aid).one()
        assert n.ack_status.value == "DONE" and n.status.value == "ACKED"
    # 정정: 진행중 → 매칭·notification 모두 복귀(ACKED 잔존 없음)
    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"department_id": dept_id, "author_name": "담당자", "body": "죄송, 아직 진행중",
                          "ack_status": "IN_PROGRESS"})
    assert r.status_code == 201, r.text
    with SessionLocal() as db:
        acks = [m.ack_status.value for m in db.query(Match).filter(Match.advisory_id == aid)]
        assert set(acks) == {"IN_PROGRESS"}
        n = db.query(Notification).filter(Notification.advisory_id == aid).one()
        assert n.ack_status.value == "IN_PROGRESS" and n.status.value == "SENT"


# ── C4: 미등록 부서명 + 조치상태 회신 → 조용한 no-op 대신 400 ──
def test_ack_comment_with_unknown_department_rejected(client, matched_advisory):
    aid = matched_advisory["aid"]
    client.post(f"/api/v1/advisories/{aid}/board")
    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"department_name": "없는부서", "author_name": "홍길동",
                          "body": "완료", "ack_status": "DONE"})
    assert r.status_code == 400
    # 상태 없는 자유 댓글은 여전히 허용(기존 동작 유지)
    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"department_name": "없는부서", "author_name": "홍길동", "body": "문의"})
    assert r.status_code == 201


# ── C6: 관리자 수동 ack → 부서 자산 매칭에 전파 ──
def test_admin_ack_patch_propagates_to_matches(client, matched_advisory):
    aid, dept_id = matched_advisory["aid"], matched_advisory["dept_id"]
    client.post(f"/api/v1/advisories/{aid}/notifications",
                json={"departments": [{"department_id": dept_id, "channels": ["MAIL"]}]})
    with SessionLocal() as db:
        nid = db.query(Notification).filter(Notification.advisory_id == aid).one().id
    r = client.patch(f"/api/v1/notifications/{nid}/ack", json={"ack_status": "DONE", "by": "관제"})
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        acks = [m.ack_status.value for m in db.query(Match).filter(Match.advisory_id == aid)]
        assert set(acks) == {"DONE"}


# ── C8: 그룹웨어 웹훅 — 다건 미종료 시 권고문 특정 강제 ──
def test_groupware_webhook_requires_advisory_when_ambiguous(client, matched_advisory):
    aid, dept_id = matched_advisory["aid"], matched_advisory["dept_id"]
    client.post(f"/api/v1/advisories/{aid}/notifications",
                json={"departments": [{"department_id": dept_id, "channels": ["MAIL"]}]})
    # 같은 부서로 두 번째 권고문 발송 → 미종료 2건
    _seed_cve("CVE-2077-4000")
    aid2 = _upload(client, ["second advisory", "CVE-2077-4000"])
    _extract_sync(client, aid2)
    assert client.post(f"/api/v1/advisories/{aid2}/match").status_code == 200
    client.post(f"/api/v1/advisories/{aid2}/notifications",
                json={"departments": [{"department_id": dept_id, "channels": ["MAIL"]}]})

    with SessionLocal() as db:
        dept_name = db.get(Department, dept_id).name
    r = signed_webhook_post(client, "/api/v1/webhooks/groupware/ack",
                            {"department": dept_name, "status": "DONE"})
    assert r.status_code == 409, r.text                 # 모호 → 특정 요구
    assert r.json()["detail"]["code"] == "AMBIGUOUS_ADVISORY"
    r = signed_webhook_post(client, "/api/v1/webhooks/groupware/ack",
                            {"department": dept_name, "status": "DONE", "advisory_id": aid})
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        n = db.query(Notification).filter(Notification.advisory_id == aid).one()
        assert n.ack_status.value == "DONE"
        n2 = db.query(Notification).filter(Notification.advisory_id == aid2).one()
        assert n2.ack_status.value == "NONE"            # 다른 권고문은 그대로


# ── A5: 마지막 CVE 삭제 — 발송 후 상태는 강등하지 않음 ──
def test_delete_last_cve_keeps_post_notify_status(client, matched_advisory):
    aid, dept_id = matched_advisory["aid"], matched_advisory["dept_id"]
    client.post(f"/api/v1/advisories/{aid}/notifications",
                json={"departments": [{"department_id": dept_id, "channels": ["MAIL"]}]})
    status_before = client.get(f"/api/v1/advisories/{aid}").json()["status"]
    assert status_before in ("NOTIFYING", "COMPLETED")
    ac_id = client.get(f"/api/v1/advisories/{aid}/cves").json()["items"][0]["id"]
    assert client.delete(f"/api/v1/advisory-cves/{ac_id}").status_code == 200
    assert client.get(f"/api/v1/advisories/{aid}").json()["status"] == status_before


# ── D1: 교체(replace) 재임포트 — 매칭 FK 보존 + 미포함 자산 RETIRED ──
def test_replace_import_with_live_matches(client, matched_advisory):
    aid = matched_advisory["aid"]
    wb = Workbook(); ws = wb.active
    ws.append(["자산번호", "사용부서", "운영체제/SW", "세부버전", "담당자"])
    ws.append(["RW-0001", "회귀검증부", "Windows 11", "23H2", "김유지"])   # 기존 유지
    ws.append(["RW-9999", "회귀검증부", "Windows 11", "23H2", "박신규"])   # 신규
    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    pv = client.post("/api/v1/assets/import/preview",
                     files={"file": ("replace.xlsx", buf,
                                     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert pv.status_code == 200
    r = client.post(f"/api/v1/assets/import/{pv.json()['import_id']}/commit",
                    json={"mapping": {"asset_no": "A", "department": "B", "product_key": "C",
                                      "version_norm": "D", "owner_name": "E"},
                          "mode": "replace", "on_warning": "skip", "header_rows": 1})
    assert r.status_code == 200, r.text                 # (기존: FK IntegrityError 500)
    body = r.json()
    assert body["committed"] == 2 and body["retired"] >= 1
    with SessionLocal() as db:
        kept = db.query(Asset).filter(Asset.asset_no == "RW-0001").one()
        gone = db.query(Asset).filter(Asset.asset_no == "RW-0002").one()
        assert kept.status.value == "NORMAL" and gone.status.value == "RETIRED"
        # 진행 중 매칭·조치 데이터 보존
        assert db.query(Match).filter(Match.advisory_id == aid).count() == 2
    # 재매칭하면 RETIRED 자산은 신규 후보에서 제외되고 기존 행은 유지(upsert)
    assert client.post(f"/api/v1/advisories/{aid}/match").status_code == 200


# ── D2: 파일 내 자산번호 중복 — 500 대신 경고 + 마지막 행 우선 ──
def test_import_duplicate_asset_no_within_file(client):
    wb = Workbook(); ws = wb.active
    ws.append(["자산번호", "사용부서", "운영체제/SW", "세부버전", "담당자"])
    ws.append(["DUP-0001", "중복검증부", "Windows 11", "22H2", "첫행"])
    ws.append(["DUP-0001", "중복검증부", "Windows 11", "23H2", "둘째행"])
    buf = io.BytesIO(); wb.save(buf); buf.seek(0)
    pv = client.post("/api/v1/assets/import/preview",
                     files={"file": ("dup.xlsx", buf,
                                     "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    r = client.post(f"/api/v1/assets/import/{pv.json()['import_id']}/commit",
                    json={"mapping": {"asset_no": "A", "department": "B", "product_key": "C",
                                      "version_norm": "D", "owner_name": "E"},
                          "mode": "append", "on_warning": "skip", "header_rows": 1})
    assert r.status_code == 200, r.text                 # (기존: UNIQUE IntegrityError 500)
    assert any(w["issue"] == "DUPLICATE_ASSET_NO" for w in r.json()["warnings"])
    with SessionLocal() as db:
        a = db.query(Asset).filter(Asset.asset_no == "DUP-0001").one()
        assert a.version_raw == "23H2"                  # 마지막 행 우선


# ── D7: 버전 비교기 — 해석 불가 텍스트·'v' 접두 ──
def test_version_rules_conservative_paths():
    from app.core.versioning import normalize_version, version_matches
    assert normalize_version("v124.0.6367.91") == "124.0.6367.91"
    # 열거 규칙 + 해석 불가 자산 버전 → 확정 미매칭이 아니라 후보
    assert version_matches("알 수 없음", ["23H2"]) == (True, True)
    # 열거 규칙 + 표기만 다른 동일 버전(v 접두)
    assert version_matches("v124", ["124"]) == (True, False)
    # 일치하지 않는 해석 가능 버전은 여전히 확정 미매칭
    assert version_matches("22H2", ["23H2"]) == (False, False)


# ── B6: 메일 채널 비활성 시 notify/test 도 실패로 일치 ──
def test_notify_test_respects_mail_enabled(client, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "MAIL_ENABLED", False)
    r = client.post("/api/v1/notify/test", json={"to": "ops@example.go.kr"})
    assert r.status_code == 200 and r.json()["ok"] is False
    assert "비활성" in r.json()["info"]
