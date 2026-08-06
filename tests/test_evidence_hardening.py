"""증빙 업로드·파일 접근 하드닝 회귀 (보안검토 H-1).

조치 전 문제
  · 익명 POST 하나로 임의 댓글의 증빙을 갈아치우고, 연결된 발송이력의 증빙 경로까지
    함께 재지정할 수 있었다 = 부서 공식 조치증빙 위조.
  · 업로드 확장자 제한이 없어 .html/.svg 를 올린 뒤 같은 오리진에서 렌더시킬 수 있었다.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from app import enums
from app.db import SessionLocal
from app.models import Advisory, AdvisoryComment, Department, Notification
from app.seed import _minimal_pdf


@pytest.fixture()
def dept_id():
    """검증용 부서 — get-or-create.

    다른 테스트가 만든 자산이 이 부서를 참조하면 teardown 의 삭제가 FK 로 막힌다.
    매번 INSERT 하면 그 다음 테스트가 UNIQUE 로 깨지므로 있으면 재사용한다.
    """
    from sqlalchemy import select

    with SessionLocal() as db:
        d = db.scalar(select(Department).where(Department.name == "증빙검증부"))
        if d is None:
            d = Department(name="증빙검증부", is_active=True)
            db.add(d)
            db.commit()
        did = d.id
    yield did
    # teardown 은 픽스처 역순이라 published_advisory 보다 먼저 돈다 — 이 부서를 참조하는
    # 발송이력을 먼저 지워야 FK 에 막히지 않는다. 그래도 다른 테스트가 만든 자산 등이
    # 남아 있을 수 있으므로 삭제 실패는 무시한다(정리 실패로 테스트를 깨뜨릴 이유가 없다).
    with SessionLocal() as db:
        db.query(Notification).filter(Notification.department_id == did).delete()
        db.commit()
    with SessionLocal() as db:
        try:
            db.query(Department).filter(Department.id == did).delete()
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()


def _make_notification(advisory_id: int, department_id: int) -> int:
    with SessionLocal() as db:
        n = Notification(advisory_id=advisory_id, department_id=department_id,
                         channels=["WEB_UI"], message_body="m", asset_ids=[],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE)
        db.add(n)
        db.commit()
        return n.id


@pytest.fixture()
def published_advisory(client):
    r = client.post("/api/v1/advisories",
                    files={"file": ("ev.pdf", _minimal_pdf("증빙 하드닝"), "application/pdf")},
                    data={"source_org": "검증기관", "title": "증빙 하드닝"})
    aid = r.json()["id"]
    assert client.post(f"/api/v1/advisories/{aid}/board").status_code == 200
    yield aid
    with SessionLocal() as db:
        db.query(AdvisoryComment).filter(AdvisoryComment.advisory_id == aid).delete()
        db.query(Notification).filter(Notification.advisory_id == aid).delete()
        db.query(Advisory).filter(Advisory.id == aid).delete()
        db.commit()


def _new_comment(public_client, aid: int, name: str = "직원") -> int:
    r = public_client.post(f"/api/v1/board/advisories/{aid}/comments",
                           json={"author_name": name, "body": "회신"})
    assert r.status_code == 201, r.text
    return r.json()["comment"]["id"]


def test_second_upload_rejected_and_original_preserved(public_client, published_advisory):
    """H-1 위조 시나리오 그대로 — 거부되고, 원본 증빙이 그대로 남아야 한다."""
    cid = _new_comment(public_client, published_advisory)
    first = public_client.post(f"/api/v1/board/comments/{cid}/evidence",
                               files={"file": ("proof.txt", b"original", "text/plain")})
    assert first.status_code == 201, first.text

    with SessionLocal() as db:
        before = db.get(AdvisoryComment, cid).evidence_path

    second = public_client.post(f"/api/v1/board/comments/{cid}/evidence",
                                files={"file": ("forged.txt", b"forged", "text/plain")})
    assert second.status_code == 409, second.text

    with SessionLocal() as db:
        after = db.get(AdvisoryComment, cid).evidence_path
    assert after == before
    assert Path(after).read_bytes() == b"original", "위조 파일이 실제로 덮어썼다"


def test_ack_evidence_link_not_hijackable(public_client, published_advisory, dept_id):
    """조치상태 회신 증빙은 발송이력에도 연결된다 — 그 링크가 탈취되지 않는지 확인.

    이 연결(board.py 의 ack 동기화)이 위조의 실제 피해 경로였다: 공격자가 증빙을 바꾸면
    부서 발송이력의 조치증빙까지 함께 바뀐다.
    """
    nid = _make_notification(published_advisory, dept_id)
    r = public_client.post(f"/api/v1/board/advisories/{published_advisory}/comments",
                           json={"author_name": "부서담당", "department_id": dept_id,
                                 "body": "조치중", "ack_status": "IN_PROGRESS"})
    cid = r.json()["comment"]["id"]

    assert public_client.post(f"/api/v1/board/comments/{cid}/evidence",
                              files={"file": ("real.txt", b"real proof", "text/plain")}
                              ).status_code == 201
    with SessionLocal() as db:
        linked = db.get(Notification, nid).ack_evidence_path

    assert public_client.post(f"/api/v1/board/comments/{cid}/evidence",
                              files={"file": ("fake.txt", b"fake", "text/plain")}
                              ).status_code == 409
    with SessionLocal() as db:
        assert db.get(Notification, nid).ack_evidence_path == linked
    assert Path(linked).read_bytes() == b"real proof"


def test_same_filename_different_comments_do_not_collide(public_client, published_advisory):
    """디스크상 파일명이 고유해야 한다 — 예전엔 comment{id}_{name} 이라 충돌 가능했다."""
    c1 = _new_comment(public_client, published_advisory, "직원1")
    c2 = _new_comment(public_client, published_advisory, "직원2")
    for cid, payload in ((c1, b"first"), (c2, b"second")):
        assert public_client.post(f"/api/v1/board/comments/{cid}/evidence",
                                  files={"file": ("proof.txt", payload, "text/plain")}
                                  ).status_code == 201
    with SessionLocal() as db:
        p1 = Path(db.get(AdvisoryComment, c1).evidence_path)
        p2 = Path(db.get(AdvisoryComment, c2).evidence_path)
        # 표시명은 원본 그대로 유지되어야 한다(난수는 디스크 경로에만).
        assert db.get(AdvisoryComment, c1).evidence_name == "proof.txt"
    assert p1 != p2
    assert p1.read_bytes() == b"first" and p2.read_bytes() == b"second"


@pytest.mark.parametrize(("filename", "content"), [
    ("evil.html", b"<html><script>alert(1)</script></html>"),
    ("evil.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script/></svg>"),
    ("evil.js", b"alert(1)"),
    ("evil.xhtml", b"<html/>"),
])
def test_scriptable_types_rejected(public_client, published_advisory, filename, content):
    """저장형 XSS 벡터는 디스크에 남기지도 않는다."""
    cid = _new_comment(public_client, published_advisory)
    r = public_client.post(f"/api/v1/board/comments/{cid}/evidence",
                           files={"file": (filename, content, "text/plain")})
    assert r.status_code == 415, r.text
    with SessionLocal() as db:
        assert db.get(AdvisoryComment, cid).evidence_path is None


def test_extension_content_mismatch_rejected(public_client, published_advisory):
    """확장자 위장(.png 인데 내용은 HTML) 차단 — content_type 은 신뢰하지 않는다."""
    cid = _new_comment(public_client, published_advisory)
    r = public_client.post(f"/api/v1/board/comments/{cid}/evidence",
                           files={"file": ("evil.png", b"<html>nope</html>", "image/png")})
    assert r.status_code == 415, r.text


def test_size_check_precedes_type_check(public_client, published_advisory):
    """초과 크기는 형식과 무관하게 413 — smoke_test 의 big.bin 계약을 지킨다."""
    from app.config import settings

    cid = _new_comment(public_client, published_advisory)
    old = settings.MAX_UPLOAD_MB
    settings.MAX_UPLOAD_MB = 0
    try:
        r = public_client.post(f"/api/v1/board/comments/{cid}/evidence",
                               files={"file": ("big.bin", b"x", "application/octet-stream")})
        assert r.status_code == 413, r.text
    finally:
        settings.MAX_UPLOAD_MB = old


def test_pdf_endpoints_set_nosniff(client, public_client, published_advisory):
    admin = client.get(f"/api/v1/advisories/{published_advisory}/file")
    assert admin.headers.get("X-Content-Type-Options") == "nosniff"
    board = public_client.get(f"/api/v1/board/advisories/{published_advisory}/file")
    assert board.headers.get("X-Content-Type-Options") == "nosniff"


def test_notification_evidence_allows_replacement(client, published_advisory, dept_id):
    """관리자 엔드포인트는 교체를 허용해야 한다(잘못 올린 파일 정정 동선).

    공개 게시판 쪽 409 와 대비되는 의도적 비대칭 — 여기는 인증된 관리자만 호출한다.
    """
    nid = _make_notification(published_advisory, dept_id)
    first = client.post(f"/api/v1/notifications/{nid}/evidence",
                        files={"file": ("a.txt", b"first", "text/plain")})
    assert first.status_code == 200, first.text
    with SessionLocal() as db:
        old_path = db.get(Notification, nid).ack_evidence_path

    second = client.post(f"/api/v1/notifications/{nid}/evidence",
                         files={"file": ("b.txt", b"second", "text/plain")})
    assert second.status_code == 200, second.text
    with SessionLocal() as db:
        n = db.get(Notification, nid)
        assert n.ack_evidence_path != old_path
        assert n.ack_evidence_name == "b.txt"
        assert Path(n.ack_evidence_path).read_bytes() == b"second"
    assert not Path(old_path).exists(), "교체된 이전 증빙이 디스크에 남았다"


@pytest.mark.skipif(sys.platform == "win32",
                    reason="Windows 는 POSIX 모드 비트 대신 NTFS ACL 을 쓴다(test_win_acl 참조)")
def test_data_dir_permissions_posix():
    from app.config import DATA_DIR, UPLOAD_DIR

    from app.routers.board import EVIDENCE_DIR
    for d in (DATA_DIR, UPLOAD_DIR, EVIDENCE_DIR):
        assert oct(os.stat(d).st_mode & 0o777) == "0o700", d
