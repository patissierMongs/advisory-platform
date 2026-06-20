"""조치기한·접수경로 추출(§8·9) + 관리자 수동 지정 PATCH."""
from __future__ import annotations

import pytest

from app import enums
from app.core import extract
from app.db import SessionLocal
from app.models import Advisory


# ── 추출(best-effort) ──
def test_extract_due_date_keyword():
    due, snip = extract.extract_due_date("조치기한: 2026. 6. 26.까지 보안 업데이트 적용")
    assert due is not None and (due.year, due.month, due.day) == (2026, 6, 26)
    assert snip


def test_extract_due_date_until_pattern():
    due, _ = extract.extract_due_date("각 기관은 2026-07-01 이내 조치 완료 후 회신")
    assert due is not None and due.isoformat() == "2026-07-01"


def test_extract_due_date_absent_returns_none():
    # 취약점 조치가이드형 — 기한 표기 없음.
    assert extract.extract_due_date("Notepad++ v8.9.2 미만의 모든 버전 영향")[0] is None


def test_extract_channel_explicit_label():
    assert extract.extract_receive_channel("접수경로: 국가사이버안보센터 전용망")[0] == "NCST"
    assert extract.extract_receive_channel("수신경로 웹메일")[0] == "WEBMAIL"
    assert extract.extract_receive_channel("접수 경로 : 공문 시행")[0] == "OFFICIAL_DOC"


def test_extract_channel_no_label_returns_none():
    # 라벨이 없으면 본문에 '국가정보원' 단어가 있어도 추정하지 않는다(오탐 방지).
    assert extract.extract_receive_channel("국가정보원에서 배포한 보안권고문")[0] is None


# ── 관리자 수동 지정 PATCH ──
@pytest.fixture()
def adv_id():
    with SessionLocal() as db:
        a = Advisory(doc_no="META-1", title="메타 테스트 권고문",
                     status=enums.AdvisoryStatus.UPLOADED)
        db.add(a)
        db.commit()
        aid = a.id
    yield aid
    with SessionLocal() as db:
        from sqlalchemy import delete
        db.execute(delete(Advisory).where(Advisory.id == aid))
        db.commit()


def test_meta_patch_sets_manual_source(client, adv_id):
    r = client.patch(f"/api/v1/advisories/{adv_id}/meta",
                     json={"due_at": "2026-08-01", "receive_channel": "OFFICIAL_DOC"})
    assert r.status_code == 200
    b = r.json()
    assert b["due_at"][:10] == "2026-08-01" and b["due_source"] == "MANUAL"
    assert b["receive_channel"] == "OFFICIAL_DOC" and b["channel_source"] == "MANUAL"


def test_meta_patch_partial_then_clear(client, adv_id):
    client.patch(f"/api/v1/advisories/{adv_id}/meta", json={"due_at": "2026-08-01"})
    # 접수경로만 변경 → 기한은 유지(부분 수정).
    b = client.patch(f"/api/v1/advisories/{adv_id}/meta",
                     json={"receive_channel": "NCST"}).json()
    assert b["due_at"][:10] == "2026-08-01" and b["receive_channel"] == "NCST"
    # 기한 비우기 → 미지정.
    b2 = client.patch(f"/api/v1/advisories/{adv_id}/meta", json={"due_at": ""}).json()
    assert b2["due_at"] is None and b2["due_source"] is None


def test_meta_patch_rejects_invalid_channel(client, adv_id):
    r = client.patch(f"/api/v1/advisories/{adv_id}/meta", json={"receive_channel": "BOGUS"})
    assert r.status_code == 400
