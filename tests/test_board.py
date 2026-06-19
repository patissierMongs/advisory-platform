"""내부 게시판(공개 열람 + 무인증 댓글 + ack 동기화) 라우트 테스트."""
from __future__ import annotations

import pytest

from app import enums
from app.db import SessionLocal
from app.models import Advisory, AdvisoryComment, Department, Notification


@pytest.fixture()
def fixture_ids():
    """부서 1 + 미공개 권고문 1 생성. 테스트 후 정리(댓글·발송 포함)."""
    with SessionLocal() as db:
        dept = Department(name="게시판테스트부서", is_active=True)
        adv = Advisory(doc_no="TEST-BOARD-1", title="테스트 보안권고문",
                       status=enums.AdvisoryStatus.EXTRACTED)
        db.add_all([dept, adv])
        db.commit()
        ids = (adv.id, dept.id)
    yield ids
    with SessionLocal() as db:
        from sqlalchemy import delete
        db.execute(delete(AdvisoryComment).where(AdvisoryComment.advisory_id == ids[0]))
        db.execute(delete(Notification).where(Notification.advisory_id == ids[0]))
        db.execute(delete(Advisory).where(Advisory.id == ids[0]))
        db.execute(delete(Department).where(Department.id == ids[1]))
        db.commit()


def test_unpublished_not_visible(client, fixture_ids):
    aid, _ = fixture_ids
    assert all(a["id"] != aid for a in client.get("/api/v1/board/advisories").json()["items"])
    assert client.get(f"/api/v1/board/advisories/{aid}").status_code == 404


def test_publish_then_visible_and_comment_flow(client, fixture_ids):
    aid, did = fixture_ids
    # 관리자 '게시판 게시' → 내부 게시판 공개
    r = client.post(f"/api/v1/advisories/{aid}/board")
    assert r.status_code == 200 and r.json()["board_published"] is True

    lst = client.get("/api/v1/board/advisories").json()["items"]
    row = next(a for a in lst if a["id"] == aid)
    assert row["comment_count"] == 0 and "max_severity" in row

    # 부서 드롭다운
    assert any(d["id"] == did for d in client.get("/api/v1/board/departments").json()["items"])

    # 무인증 일반 댓글
    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"author_name": "홍길동", "body": "확인했습니다", "department_name": "직접입력팀"})
    assert r.status_code == 201
    assert r.json()["comment"]["department"] == "직접입력팀"

    d = client.get(f"/api/v1/board/advisories/{aid}").json()
    assert len(d["comments"]) == 1

    # 빈 본문/이름은 거부
    assert client.post(f"/api/v1/board/advisories/{aid}/comments",
                       json={"author_name": "x", "body": ""}).status_code == 422


def test_ack_status_syncs_to_notification(client, fixture_ids):
    aid, did = fixture_ids
    client.post(f"/api/v1/advisories/{aid}/board")
    with SessionLocal() as db:
        n = Notification(advisory_id=aid, department_id=did, channels=["WEB_UI"],
                         message_body="m", asset_ids=[], status=enums.NotificationStatus.SENT,
                         ack_status=enums.AckStatus.NONE)
        db.add(n)
        db.commit()
        nid = n.id

    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"author_name": "담당자", "department_id": did,
                          "body": "조치 완료", "ack_status": "DONE"})
    assert r.status_code == 201 and r.json()["ack_synced_notification"] == nid

    with SessionLocal() as db:
        n = db.get(Notification, nid)
        assert n.ack_status == enums.AckStatus.DONE
        assert n.status == enums.NotificationStatus.ACKED
        assert n.ack_by == "담당자" and n.ack_note == "조치 완료"


def test_unpublish_hides_but_keeps_comments(client, fixture_ids):
    aid, _ = fixture_ids
    client.post(f"/api/v1/advisories/{aid}/board")
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "갑", "body": "댓글"})
    assert client.post(f"/api/v1/advisories/{aid}/board-unpublish").status_code == 200
    assert all(a["id"] != aid for a in client.get("/api/v1/board/advisories").json()["items"])
    # 댓글은 보존(언게시는 숨김만)
    with SessionLocal() as db:
        from sqlalchemy import func, select
        cnt = db.scalar(select(func.count(AdvisoryComment.id)).where(AdvisoryComment.advisory_id == aid))
    assert cnt == 1


def test_delete_comment(client, fixture_ids):
    aid, _ = fixture_ids
    client.post(f"/api/v1/advisories/{aid}/board")
    cid = client.post(f"/api/v1/board/advisories/{aid}/comments",
                      json={"author_name": "을", "body": "삭제될 댓글"}).json()["comment"]["id"]
    assert client.delete(f"/api/v1/board/comments/{cid}").status_code == 204
    assert client.get(f"/api/v1/board/advisories/{aid}").json()["comments"] == []
