"""내부 게시판(공개 열람 + 무인증 댓글 + ack 동기화) 라우트 테스트."""
from __future__ import annotations

import pytest

from datetime import datetime

from app import enums
from app.db import SessionLocal
from app.models import (
    Advisory, AdvisoryComment, AdvisoryCve, Asset, Department, Match, Notification,
)


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


def test_department_filter_and_exclude_done(client):
    """부서별 필터 + 완료 제외(기본) 동작."""
    from sqlalchemy import delete
    with SessionLocal() as db:
        a_pub = Advisory(doc_no="FLT-PUB", title="공개 권고문", status=enums.AdvisoryStatus.MATCHED)
        a_done = Advisory(doc_no="FLT-DONE", title="완료 권고문", status=enums.AdvisoryStatus.COMPLETED)
        dA = Department(name="필터부서A", is_active=True)
        dB = Department(name="필터부서B", is_active=True)
        dC = Department(name="필터부서C", is_active=True)
        db.add_all([a_pub, a_done, dA, dB, dC])
        db.commit()
        ids = dict(pub=a_pub.id, done=a_done.id, A=dA.id, B=dB.id, C=dC.id)
        # 둘 다 게시판 공개
        for aid in (ids["pub"], ids["done"]):
            db.get(Advisory, aid).board_published_at = __import__("datetime").datetime.now()
        # pub: A=미회신, B=조치완료 / done: A=미회신
        db.add_all([
            Notification(advisory_id=ids["pub"], department_id=ids["A"], channels=[], asset_ids=[],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE),
            Notification(advisory_id=ids["pub"], department_id=ids["B"], channels=[], asset_ids=[],
                         status=enums.NotificationStatus.ACKED, ack_status=enums.AckStatus.DONE),
            Notification(advisory_id=ids["done"], department_id=ids["A"], channels=[], asset_ids=[],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE),
        ])
        db.commit()

    def board(**q):
        from urllib.parse import urlencode
        return {a["doc_no"]: a for a in client.get("/api/v1/board/advisories?"+urlencode(q)).json()["items"]}

    try:
        # 기본(부서 미지정, 완료 제외 ON): COMPLETED 권고문 제외
        b = board(exclude_done=True)
        assert "FLT-PUB" in b and "FLT-DONE" not in b
        # 완료 제외 OFF: 둘 다 보임
        b = board(exclude_done=False)
        assert "FLT-PUB" in b and "FLT-DONE" in b

        # 부서 A: 두 권고문 모두 관련. 완료 제외 ON이어도 A는 미회신이라 둘 다 남음
        b = board(department_id=ids["A"], exclude_done=True)
        assert "FLT-PUB" in b and "FLT-DONE" in b
        assert b["FLT-PUB"]["dept_ack_status"] == "NONE"

        # 부서 B: pub 만 관련, 그리고 B는 조치완료 → 완료 제외 ON이면 사라짐
        assert board(department_id=ids["B"], exclude_done=True) == {}
        b = board(department_id=ids["B"], exclude_done=False)
        assert "FLT-PUB" in b and b["FLT-PUB"]["dept_ack_status"] == "DONE"

        # 부서 C: 관련 권고문 없음
        assert board(department_id=ids["C"], exclude_done=False) == {}
    finally:
        with SessionLocal() as db:
            db.execute(delete(Notification).where(Notification.advisory_id.in_([ids["pub"], ids["done"]])))
            db.execute(delete(Advisory).where(Advisory.id.in_([ids["pub"], ids["done"]])))
            db.execute(delete(Department).where(Department.id.in_([ids["A"], ids["B"], ids["C"]])))
            db.commit()


def test_board_surfaces_affected_dept_asset_owner(client):
    """게시판이 매칭된 부서·자산·담당자를 노출."""
    from sqlalchemy import delete
    with SessionLocal() as db:
        dept = Department(name="영향테스트부서", is_active=True)
        db.add(dept)
        db.commit()
        did = dept.id
        asset = Asset(asset_no="IMP-A1", department_id=did, product_key="google_chrome",
                      product_raw="Google Chrome", version_raw="120", owner_name="김담당",
                      owner_contact="010-1234-5678", status=enums.AssetStatus.NORMAL)
        adv = Advisory(doc_no="IMP-1", title="크롬 취약점", status=enums.AdvisoryStatus.MATCHED)
        db.add_all([asset, adv])
        db.commit()
        aid, asid = adv.id, asset.id
        ac = AdvisoryCve(advisory_id=aid, cve_id_text="CVE-2026-30012",
                         lookup_status=enums.LookupStatus.FOUND)
        db.add(ac)
        db.commit()
        db.add(Match(advisory_id=aid, advisory_cve_id=ac.id, asset_id=asid,
                     status=enums.MatchStatus.MATCHED))
        db.get(Advisory, aid).board_published_at = datetime.now()
        db.commit()
    try:
        items = client.get("/api/v1/board/advisories?exclude_done=false").json()["items"]
        row = next(a for a in items if a["doc_no"] == "IMP-1")
        assert row["affected_dept_count"] == 1 and row["affected_asset_count"] == 1
        ad = row["affected_departments"][0]
        assert ad["name"] == "영향테스트부서" and ad["asset_count"] == 1 and "김담당" in ad["owners"]
        assert "Google Chrome" in row["affected_products"]

        d = client.get(f"/api/v1/board/advisories/{aid}").json()
        assert len(d["matches"]) == 1
        m = d["matches"][0]
        assert m["owner_name"] == "김담당" and m["owner_contact"] == "010-1234-5678"
        assert m["department"] == "영향테스트부서"
    finally:
        with SessionLocal() as db:
            db.execute(delete(Match).where(Match.advisory_id == aid))
            db.execute(delete(AdvisoryCve).where(AdvisoryCve.advisory_id == aid))
            db.execute(delete(Advisory).where(Advisory.id == aid))
            db.execute(delete(Asset).where(Asset.id == asid))
            db.execute(delete(Department).where(Department.id == did))
            db.commit()


def test_delete_comment(client, fixture_ids):
    aid, _ = fixture_ids
    client.post(f"/api/v1/advisories/{aid}/board")
    cid = client.post(f"/api/v1/board/advisories/{aid}/comments",
                      json={"author_name": "을", "body": "삭제될 댓글"}).json()["comment"]["id"]
    assert client.delete(f"/api/v1/board/comments/{cid}").status_code == 204
    assert client.get(f"/api/v1/board/advisories/{aid}").json()["comments"] == []
