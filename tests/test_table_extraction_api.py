"""표 기반 추출 종단 회귀 — 업로드 → 추출 → 목록 응답까지.

표 서식 판정(table_status)은 관리자가 '손봐야 할 권고문'을 목록에서 즉시 골라내는 근거다.
여기서는 그 값이 실제 업로드 경로를 통해 정확히 매겨지는지, 그리고 표에서 뽑은 제품·버전이
DB 에 그대로 들어가 자산 매칭에 쓰이는지를 확인한다.
"""
from __future__ import annotations

import io
import time

import pytest
from sqlalchemy import select

from app.core.pdf_tables import NO_TABLE, TABLE_OK, TABLE_UNPARSED
from app.core.versioning import version_matches
from app.db import SessionLocal
from app.models import Advisory, AdvisoryCve, AdvisoryIndex, AdvisoryProduct
from app.seed import _minimal_pdf
from tests.test_pdf_tables import COLS4, HEADER4, build_pdf, layout


def _upload(client, pdf_bytes: bytes, title: str) -> int:
    r = client.post("/api/v1/advisories",
                    files={"file": (f"{title}.pdf", io.BytesIO(pdf_bytes), "application/pdf")},
                    data={"source_org": "검증기관", "title": title})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _extract_and_wait(client, aid: int, timeout: float = 20.0) -> dict:
    assert client.post(f"/api/v1/advisories/{aid}/extract").status_code == 200
    deadline = time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/api/v1/advisories/{aid}").json()
        if body.get("extract_phase") in ("done", "failed"):
            return body
        time.sleep(0.1)
    pytest.fail("추출이 시간 내에 끝나지 않았다")


@pytest.fixture()
def cleanup_advisories():
    created: list[int] = []
    yield created
    with SessionLocal() as db:      # FK 순서 준수(자식 → 부모)
        for aid in created:
            db.query(AdvisoryProduct).filter(AdvisoryProduct.advisory_id == aid).delete()
            db.query(AdvisoryCve).filter(AdvisoryCve.advisory_id == aid).delete()
            db.query(AdvisoryIndex).filter(AdvisoryIndex.advisory_id == aid).delete()
            db.query(Advisory).filter(Advisory.id == aid).delete()
        db.commit()


def test_table_advisory_extracts_products_and_marks_table_ok(client, cleanup_advisories):
    """사용자 예시 표 그대로 — 같은 제품 두 범위가 살아남고 매칭까지 동작해야 한다."""
    body = [["CVE-2026-8461", "FFmpeg", "8.1.0 to 8.1.2", "8.1.2"],
            ["", "", "8.0.0 to 8.0.3", "8.1.3"],
            ["CVE-2026-9001", "OpenSSL", "3.0.0 to 3.0.14", "3.0.15"]]
    aid = _upload(client, build_pdf([layout(COLS4, HEADER4, body)]), "표형태권고문")
    cleanup_advisories.append(aid)

    detail = _extract_and_wait(client, aid)
    assert detail["extract_phase"] == "done", detail.get("error_message")
    assert detail["table_status"] == TABLE_OK, detail

    with SessionLocal() as db:
        prods = {p.product_key: p for p in db.scalars(
            select(AdvisoryProduct).where(AdvisoryProduct.advisory_id == aid)).all()}
    assert "ffmpeg" in prods and "openssl" in prods, list(prods)

    rule = prods["ffmpeg"].affected_versions
    assert "any" in rule and len(rule["any"]) == 2, rule
    # 두 범위 모두 실제로 매칭돼야 한다 — 하나만 살아남으면 취약 자산이 조용히 누락된다.
    assert version_matches("8.1.1", rule) == (True, False)
    assert version_matches("8.0.2", rule) == (True, False)
    # 두 범위 어디에도 안 드는 버전은 확정 미매칭.
    # (ASCII 픽스처라 영문 'A to B' 를 썼고 이 형태는 경계 포함이다 — 한국어 '미만'의
    #  배타 경계는 test_product_extract 의 gte/lt 케이스가 따로 고정한다.)
    assert version_matches("8.1.3", rule) == (False, False)
    assert version_matches("7.9.0", rule) == (False, False)
    assert prods["ffmpeg"].fixed_version == "8.1.2, 8.1.3"


def test_prose_advisory_is_marked_no_table(client, cleanup_advisories):
    """산문형 권고문 — 표가 없다고 표시되고, 기존 정규식 경로가 계속 동작해야 한다."""
    aid = _upload(client, _minimal_pdf(["Security notice", "CVE-2026-21345 affects systems."]),
                  "산문형권고문")
    cleanup_advisories.append(aid)

    detail = _extract_and_wait(client, aid)
    assert detail["table_status"] == NO_TABLE, detail
    assert detail["extract_phase"] == "done"


def test_header_only_table_is_marked_unparsed(client, cleanup_advisories):
    """헤더는 있는데 본문 행이 없는 표 — '표 없음' 과 구분돼야 관리자가 원인을 안다."""
    aid = _upload(client, build_pdf([layout(COLS4, HEADER4, [])]), "빈표권고문")
    cleanup_advisories.append(aid)

    detail = _extract_and_wait(client, aid)
    assert detail["table_status"] == TABLE_UNPARSED, detail


def test_table_status_is_exposed_in_admin_list(client, cleanup_advisories):
    body = [["CVE-2026-2222", "Nginx", "1.24.0 to 1.25.3", "1.25.4"]]
    aid = _upload(client, build_pdf([layout(COLS4, HEADER4, body)]), "목록노출검증")
    cleanup_advisories.append(aid)
    _extract_and_wait(client, aid)

    items = client.get("/api/v1/advisories").json()["items"]
    row = next(a for a in items if a["id"] == aid)
    assert row["table_status"] == TABLE_OK


def test_table_status_is_hidden_from_public_board(client, public_client, cleanup_advisories):
    """추출 품질은 내부 처리 정보 — 사내 게시판에 새어 나가면 안 된다."""
    body = [["CVE-2026-3333", "Redis", "7.2.0 to 7.2.4", "7.2.5"]]
    aid = _upload(client, build_pdf([layout(COLS4, HEADER4, body)]), "게시판비노출검증")
    cleanup_advisories.append(aid)
    _extract_and_wait(client, aid)
    assert client.post(f"/api/v1/advisories/{aid}/board").status_code == 200

    detail = public_client.get(f"/api/v1/board/advisories/{aid}").json()
    assert "table_status" not in detail, detail.keys()
    listed = public_client.get("/api/v1/board/advisories?exclude_done=false").json()["items"]
    row = next(a for a in listed if a["id"] == aid)
    assert "table_status" not in row


def test_reextract_keeps_table_status_current(client, cleanup_advisories):
    """수동 재추출도 같은 경로를 타야 한다(라우터가 아니라 병합 함수에 물려 있으므로)."""
    body = [["CVE-2026-4444", "curl", "8.5.0 to 8.6.0", "8.6.0"]]
    aid = _upload(client, build_pdf([layout(COLS4, HEADER4, body)]), "재추출검증")
    cleanup_advisories.append(aid)
    _extract_and_wait(client, aid)

    with SessionLocal() as db:      # 상태를 일부러 지워 재추출이 다시 채우는지 본다
        db.get(Advisory, aid).table_status = None
        db.commit()

    r = client.post(f"/api/v1/advisories/{aid}/products/reextract")
    assert r.status_code == 200, r.text
    with SessionLocal() as db:
        assert db.get(Advisory, aid).table_status == TABLE_OK


def test_admin_edited_products_survive_reextract(client, cleanup_advisories):
    """표 경로가 관리자 확인/수동 행을 덮어쓰면 안 된다(병합 규칙 보존 확인)."""
    body = [["CVE-2026-5555", "Vim", "9.0.0 to 9.1.0", "9.1.0"]]
    aid = _upload(client, build_pdf([layout(COLS4, HEADER4, body)]), "관리자보존검증")
    cleanup_advisories.append(aid)
    _extract_and_wait(client, aid)

    with SessionLocal() as db:      # 관리자가 확인 처리한 것으로 표시
        p = db.scalar(select(AdvisoryProduct).where(AdvisoryProduct.advisory_id == aid,
                                                    AdvisoryProduct.product_key == "vim"))
        assert p is not None
        p.status = "CONFIRMED"
        p.product_name = "관리자가 고친 이름"
        db.commit()

    assert client.post(f"/api/v1/advisories/{aid}/products/reextract").status_code == 200
    with SessionLocal() as db:
        p = db.scalar(select(AdvisoryProduct).where(AdvisoryProduct.advisory_id == aid,
                                                    AdvisoryProduct.product_key == "vim"))
        assert p.status == "CONFIRMED"
        assert p.product_name == "관리자가 고친 이름", "재추출이 관리자 수정을 덮어썼다"
