"""다중 증빙(§증빙) — 여러 파일 첨부·누적 동기화·한글 파일명 열람(500 회귀)."""
from __future__ import annotations

import io


def _setup_notified_advisory(client):
    """부서 + 발송 내역 + 게시판 공개 권고문 한 벌 구성."""
    import uuid

    from app import enums
    from app.db import SessionLocal
    from app.models import Advisory, Department, Notification
    from datetime import datetime, timezone

    pdf_head = b"%PDF-1.4 " + uuid.uuid4().hex.encode()   # sha 중복(409) 회피 — 테스트별 고유
    r = client.post("/api/v1/advisories",
                    files={"file": ("ev-multi.pdf", io.BytesIO(pdf_head), "application/pdf")},
                    data={"source_org": "KISA"})
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    with SessionLocal() as db:
        dept = Department(name=f"증빙부서{aid}")
        db.add(dept)
        db.flush()
        adv = db.get(Advisory, aid)
        adv.board_published_at = datetime.now(timezone.utc)
        n = Notification(advisory_id=aid, department_id=dept.id,
                         status=enums.NotificationStatus.SENT)
        db.add(n)
        db.flush()
        ids = (aid, dept.id, n.id)
        db.commit()
    return ids


def test_comment_multi_files_and_accumulating_sync(client):
    aid, did, nid = _setup_notified_advisory(client)
    c1 = client.post(f"/api/v1/board/advisories/{aid}/comments",
                     json={"author_name": "담당자", "department_id": did,
                           "body": "1차 조치", "ack_status": "IN_PROGRESS"}).json()["comment"]["id"]
    # 한 번에 여러 파일 첨부(같은 필드명 반복).
    r = client.post(f"/api/v1/board/comments/{c1}/evidence", files=[
        ("file", ("패치결과.png", b"\x89PNG x", "image/png")),
        ("file", ("재부팅로그.txt", b"rebooted", "text/plain")),
    ])
    assert r.status_code == 201
    cm = r.json()["comment"]
    assert [f["name"] for f in cm["evidence_files"]] == ["패치결과.png", "재부팅로그.txt"]

    # 두 번째 댓글의 첨부도 발송이력 증빙에 '누적' — 이전 첨부가 사라지지 않는다.
    c2 = client.post(f"/api/v1/board/advisories/{aid}/comments",
                     json={"author_name": "담당자", "department_id": did,
                           "body": "2차 완료", "ack_status": "DONE"}).json()["comment"]["id"]
    client.post(f"/api/v1/board/comments/{c2}/evidence", files=[
        ("file", ("최종보고.txt", b"done", "text/plain")),
    ])
    roll = client.get("/api/v1/history/advisories").json()["items"]
    d = next(a for a in roll if a["id"] == aid)["departments"][0]
    assert d["has_evidence"] is True
    assert [f["name"] for f in d["evidence_files"]] == ["패치결과.png", "재부팅로그.txt", "최종보고.txt"]

    # 인덱스 열람 — 각 파일이 해당 내용으로 서빙된다.
    assert client.get(f"/api/v1/notifications/{nid}/evidence?i=2").content == b"done"
    assert client.get(f"/api/v1/board/comments/{c1}/evidence?i=1").content == b"rebooted"
    assert client.get(f"/api/v1/board/comments/{c1}/evidence?i=9").status_code == 404


def test_korean_filename_evidence_view_no_500(client):
    """한글 파일명 증빙 열람 시 latin-1 헤더 인코딩 500 회귀(현장 로그) 방지."""
    aid, did, nid = _setup_notified_advisory(client)
    cid = client.post(f"/api/v1/board/advisories/{aid}/comments",
                      json={"author_name": "담당자", "department_id": did,
                            "body": "증빙", "ack_status": "DONE"}).json()["comment"]["id"]
    client.post(f"/api/v1/board/comments/{cid}/evidence", files=[
        ("file", ("조치 완료 증빙자료.txt", "완료했습니다".encode(), "text/plain")),
    ])
    r = client.get(f"/api/v1/board/comments/{cid}/evidence")
    assert r.status_code == 200
    assert "filename*=utf-8''" in r.headers["content-disposition"].lower()
    assert r.headers["x-content-type-options"] == "nosniff"


def test_admin_additional_upload_appends(client):
    """관리자 추가 업로드(발송이력) — 기존 담당자 첨부 뒤에 누적."""
    aid, did, nid = _setup_notified_advisory(client)
    client.post(f"/api/v1/notifications/{nid}/evidence",
                files=[("file", ("현장사진.png", b"\x89PNG a", "image/png"))])
    r = client.post(f"/api/v1/notifications/{nid}/evidence", files=[
        ("file", ("관리자보완1.txt", b"a1", "text/plain")),
        ("file", ("관리자보완2.txt", b"a2", "text/plain")),
    ])
    assert r.status_code == 200
    names = [f["name"] for f in r.json()["evidence_files"]]
    assert names == ["현장사진.png", "관리자보완1.txt", "관리자보완2.txt"]
