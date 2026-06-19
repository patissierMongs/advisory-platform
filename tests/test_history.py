"""발송이력·조치관리 — 롤업/프리셋/댓글 증빙 동기화 라우트 테스트."""
from __future__ import annotations

import pytest

from app import enums
from app.db import SessionLocal
from app.models import (
    Advisory, AdvisoryComment, Department, MessageTemplate, Notification,
)


@pytest.fixture()
def hist_ids():
    """부서 1 + 발송 내역 1건이 있는 권고문 1 생성. 테스트 후 정리."""
    with SessionLocal() as db:
        dept = Department(name="이력테스트부서", is_active=True)
        adv = Advisory(doc_no="TEST-HIST-1", title="이력 테스트 권고문",
                       status=enums.AdvisoryStatus.NOTIFYING)
        db.add_all([dept, adv])
        db.commit()
        n = Notification(advisory_id=adv.id, department_id=dept.id, asset_ids=[],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE)
        db.add(n)
        db.commit()
        ids = (adv.id, dept.id, n.id)
    yield ids
    with SessionLocal() as db:
        from sqlalchemy import delete
        db.execute(delete(AdvisoryComment).where(AdvisoryComment.advisory_id == ids[0]))
        db.execute(delete(Notification).where(Notification.advisory_id == ids[0]))
        db.execute(delete(Advisory).where(Advisory.id == ids[0]))
        db.execute(delete(Department).where(Department.id == ids[1]))
        db.commit()


def test_history_rollup_lists_sent_advisory(client, hist_ids):
    aid, did, nid = hist_ids
    items = client.get("/api/v1/history/advisories").json()["items"]
    row = next(a for a in items if a["id"] == aid)
    assert row["dept_total"] == 1
    assert row["none"] == 1 and row["done"] == 0
    assert row["done_rate"] == 0
    d = row["departments"][0]
    assert d["notification_id"] == nid and d["ack_status"] == "NONE"
    assert d["has_evidence"] is False


def test_message_template_crud(client):
    created = client.post("/api/v1/message-templates",
                          json={"title": "긴급 안내", "body": "[긴급] {제목} 즉시 조치 바랍니다."})
    assert created.status_code == 201
    tid = created.json()["id"]
    assert any(t["id"] == tid for t in client.get("/api/v1/message-templates").json()["items"])
    assert client.delete(f"/api/v1/message-templates/{tid}").status_code == 204
    assert all(t["id"] != tid for t in client.get("/api/v1/message-templates").json()["items"])
    assert client.delete(f"/api/v1/message-templates/{tid}").status_code == 404


def test_comment_evidence_syncs_to_notification(client, hist_ids):
    aid, did, nid = hist_ids
    # 게시판 공개 후, 조치완료 회신 댓글(부서 식별) → 발송 ack 동기화.
    client.post(f"/api/v1/advisories/{aid}/board")
    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"author_name": "김조치", "body": "패치 완료했습니다.",
                          "department_id": did, "ack_status": "DONE"})
    assert r.status_code == 201
    cid = r.json()["comment"]["id"]

    # 댓글에 증빙 첨부 → 댓글 + 동기화된 발송이력 양쪽에 반영.
    up = client.post(f"/api/v1/board/comments/{cid}/evidence",
                     files={"file": ("patch.png", b"\x89PNG\r\n\x1a\nfake", "image/png")})
    assert up.status_code == 201
    assert up.json()["ack_synced_notification"] == nid
    assert up.json()["comment"]["has_evidence"] is True

    # 발송이력 증빙 다운로드 + 히스토리 롤업에 노출.
    assert client.get(f"/api/v1/notifications/{nid}/evidence").status_code == 200
    assert client.get(f"/api/v1/board/comments/{cid}/evidence").status_code == 200
    items = client.get("/api/v1/history/advisories").json()["items"]
    d = next(a for a in items if a["id"] == aid)["departments"][0]
    assert d["has_evidence"] is True and d["evidence"] == "patch.png"
    assert d["ack_status"] == "DONE"


def test_board_shows_progress_and_comment_evidence(client, hist_ids):
    aid, did, nid = hist_ids
    client.post(f"/api/v1/advisories/{aid}/board")

    # 게시판 목록에 진행현황(발송 대상 부서 ack 집계) 노출.
    row = next(a for a in client.get("/api/v1/board/advisories?exclude_done=false").json()["items"]
               if a["id"] == aid)
    assert row["progress"]["total"] == 1 and row["progress"]["done"] == 0

    # 댓글 + 증빙 → 상세 progress 가 완료로, 부서별 증빙 표시.
    cid = client.post(f"/api/v1/board/advisories/{aid}/comments",
                      json={"author_name": "박담당", "body": "조치했습니다",
                            "department_id": did, "ack_status": "DONE"}).json()["comment"]["id"]
    client.post(f"/api/v1/board/comments/{cid}/evidence",
                files={"file": ("ev.png", b"x", "image/png")})

    detail = client.get(f"/api/v1/board/advisories/{aid}").json()
    assert detail["progress"]["done"] == 1 and detail["progress"]["done_rate"] == 100
    dep = detail["progress"]["departments"][0]
    assert dep["ack_status"] == "DONE" and dep["has_evidence"] is True
    # 댓글에도 증빙 표식.
    assert any(c["id"] == cid and c["has_evidence"] for c in detail["comments"])
