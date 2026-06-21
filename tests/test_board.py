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


def test_comment_evidence_upload_syncs_and_sanitizes_filename(client, fixture_ids):
    """게시판 회신 증빙은 안전 파일명으로 저장되고 해당 부서 발송이력에도 연결된다."""
    from pathlib import Path

    from app.routers.board import EVIDENCE_DIR

    aid, did = fixture_ids
    client.post(f"/api/v1/advisories/{aid}/board")
    with SessionLocal() as db:
        n = Notification(advisory_id=aid, department_id=did, channels=["WEB_UI"],
                         message_body="m", asset_ids=[], status=enums.NotificationStatus.SENT,
                         ack_status=enums.AckStatus.NONE)
        db.add(n)
        db.commit()
        nid = n.id

    cid = client.post(
        f"/api/v1/board/advisories/{aid}/comments",
        json={"author_name": "증빙담당", "department_id": did,
              "body": "조치 진행 증빙 첨부", "ack_status": "IN_PROGRESS"},
    ).json()["comment"]["id"]

    r = client.post(
        f"/api/v1/board/comments/{cid}/evidence",
        files={"file": ("dept/../../evidence?.txt", b"proof", "text/plain")},
    )
    assert r.status_code == 201
    body = r.json()
    assert body["ack_synced_notification"] == nid
    assert body["comment"]["evidence"] == "evidence_.txt"

    saved = None
    with SessionLocal() as db:
        c = db.get(AdvisoryComment, cid)
        n = db.get(Notification, nid)
        saved = Path(c.evidence_path)
        assert saved.parent == EVIDENCE_DIR
        assert saved.name == f"comment{cid}_evidence_.txt"
        assert c.evidence_name == "evidence_.txt"
        assert n.ack_evidence_path == c.evidence_path
        assert n.ack_evidence_name == "evidence_.txt"
    assert saved.read_bytes() == b"proof"
    saved.unlink(missing_ok=True)


def test_comment_evidence_rejects_oversize(client, fixture_ids):
    """게시판 증빙에도 공통 업로드 크기 제한을 적용한다."""
    from app.config import settings

    aid, _ = fixture_ids
    client.post(f"/api/v1/advisories/{aid}/board")
    cid = client.post(
        f"/api/v1/board/advisories/{aid}/comments",
        json={"author_name": "파일담당", "body": "증빙 첨부 예정"},
    ).json()["comment"]["id"]

    old_limit = settings.MAX_UPLOAD_MB
    settings.MAX_UPLOAD_MB = 0
    try:
        r = client.post(
            f"/api/v1/board/comments/{cid}/evidence",
            files={"file": ("too-big.txt", b"x", "text/plain")},
        )
        assert r.status_code == 413
        with SessionLocal() as db:
            c = db.get(AdvisoryComment, cid)
            assert c.evidence_path is None and c.evidence_name is None
    finally:
        settings.MAX_UPLOAD_MB = old_limit


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
        a_sent = Advisory(doc_no="FLT-SENT", title="발송완료 미회신 권고문",
                          status=enums.AdvisoryStatus.COMPLETED)
        a_closed = Advisory(doc_no="FLT-CLOSED", title="전체 조치완료 권고문",
                            status=enums.AdvisoryStatus.COMPLETED)
        dA = Department(name="필터부서A", is_active=True)
        dB = Department(name="필터부서B", is_active=True)
        dC = Department(name="필터부서C", is_active=True)
        db.add_all([a_pub, a_sent, a_closed, dA, dB, dC])
        db.commit()
        ids = dict(pub=a_pub.id, sent=a_sent.id, closed=a_closed.id, A=dA.id, B=dB.id, C=dC.id)
        # 둘 다 게시판 공개
        for aid in (ids["pub"], ids["sent"], ids["closed"]):
            db.get(Advisory, aid).board_published_at = __import__("datetime").datetime.now()
        # pub: A=미회신, B=조치완료 / sent: A=미회신 / closed: A=조치완료
        db.add_all([
            Notification(advisory_id=ids["pub"], department_id=ids["A"], channels=[], asset_ids=[],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE),
            Notification(advisory_id=ids["pub"], department_id=ids["B"], channels=[], asset_ids=[],
                         status=enums.NotificationStatus.ACKED, ack_status=enums.AckStatus.DONE),
            Notification(advisory_id=ids["sent"], department_id=ids["A"], channels=[], asset_ids=[],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE),
            Notification(advisory_id=ids["closed"], department_id=ids["A"], channels=[], asset_ids=[],
                         status=enums.NotificationStatus.ACKED, ack_status=enums.AckStatus.DONE),
        ])
        db.commit()

    def board(**q):
        from urllib.parse import urlencode
        return {a["doc_no"]: a for a in client.get("/api/v1/board/advisories?"+urlencode(q)).json()["items"]}

    try:
        # 기본(부서 미지정, 완료 제외 ON): 발송완료(COMPLETED)여도 미회신 부서가 있으면 보여준다.
        b = board(exclude_done=True)
        assert "FLT-PUB" in b and "FLT-SENT" in b and "FLT-CLOSED" not in b
        # 완료 제외 OFF: 전체 보임
        b = board(exclude_done=False)
        assert "FLT-PUB" in b and "FLT-SENT" in b and "FLT-CLOSED" in b

        # 부서 A: pub/sent 는 미회신이라 남고, closed 는 A가 조치완료라 제외됨
        b = board(department_id=ids["A"], exclude_done=True)
        assert "FLT-PUB" in b and "FLT-SENT" in b and "FLT-CLOSED" not in b
        assert b["FLT-PUB"]["dept_ack_status"] == "NONE"

        # 부서 B: pub 만 관련, 그리고 B는 조치완료 → 완료 제외 ON이면 사라짐
        assert board(department_id=ids["B"], exclude_done=True) == {}
        b = board(department_id=ids["B"], exclude_done=False)
        assert "FLT-PUB" in b and b["FLT-PUB"]["dept_ack_status"] == "DONE"

        # 부서 C: 관련 권고문 없음
        assert board(department_id=ids["C"], exclude_done=False) == {}
    finally:
        with SessionLocal() as db:
            db.execute(delete(Notification).where(Notification.advisory_id.in_(
                [ids["pub"], ids["sent"], ids["closed"]]
            )))
            db.execute(delete(Advisory).where(Advisory.id.in_(
                [ids["pub"], ids["sent"], ids["closed"]]
            )))
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

        # 자유 검색 — 자산번호 / 담당자명 / 부서명 / 제목 부분일치
        for term in ("IMP-A1", "김담당", "영향테스트부서", "크롬"):
            hits = client.get("/api/v1/board/advisories",
                              params={"q": term, "exclude_done": "false"}).json()["items"]
            assert any(x["doc_no"] == "IMP-1" for x in hits), term
        miss = client.get("/api/v1/board/advisories",
                          params={"q": "존재하지않는zzz", "exclude_done": "false"}).json()["items"]
        assert all(x["doc_no"] != "IMP-1" for x in miss)
    finally:
        with SessionLocal() as db:
            db.execute(delete(Match).where(Match.advisory_id == aid))
            db.execute(delete(AdvisoryCve).where(AdvisoryCve.advisory_id == aid))
            db.execute(delete(Advisory).where(Advisory.id == aid))
            db.execute(delete(Asset).where(Asset.id == asid))
            db.execute(delete(Department).where(Department.id == did))
            db.commit()


def test_department_scoped_detail_hides_other_department_data(client):
    """부서 선택 상세는 다른 부서 자산·진행현황·댓글을 응답하지 않는다."""
    from sqlalchemy import delete

    with SessionLocal() as db:
        dA = Department(name="스코프부서A", is_active=True)
        dB = Department(name="스코프부서B", is_active=True)
        db.add_all([dA, dB])
        db.commit()
        aA = Asset(asset_no="SCOPE-A1", department_id=dA.id, product_key="chrome",
                   product_raw="Chrome", version_raw="120", owner_name="A담당",
                   status=enums.AssetStatus.NORMAL)
        aB = Asset(asset_no="SCOPE-B1", department_id=dB.id, product_key="office",
                   product_raw="Office", version_raw="2021", owner_name="B담당",
                   status=enums.AssetStatus.NORMAL)
        adv = Advisory(doc_no="SCOPE-1", title="부서별 스코프 테스트",
                       status=enums.AdvisoryStatus.MATCHED)
        db.add_all([aA, aB, adv])
        db.commit()
        acA = AdvisoryCve(advisory_id=adv.id, cve_id_text="CVE-2026-71001",
                          lookup_status=enums.LookupStatus.FOUND)
        acB = AdvisoryCve(advisory_id=adv.id, cve_id_text="CVE-2026-71002",
                          lookup_status=enums.LookupStatus.FOUND)
        db.add_all([acA, acB])
        db.commit()
        db.add_all([
            Match(advisory_id=adv.id, advisory_cve_id=acA.id, asset_id=aA.id,
                  status=enums.MatchStatus.MATCHED),
            Match(advisory_id=adv.id, advisory_cve_id=acB.id, asset_id=aB.id,
                  status=enums.MatchStatus.MATCHED),
            Notification(advisory_id=adv.id, department_id=dA.id, channels=[], asset_ids=[aA.id],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE),
            Notification(advisory_id=adv.id, department_id=dB.id, channels=[], asset_ids=[aB.id],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE),
            AdvisoryComment(advisory_id=adv.id, author_name="A작성자", author_department_id=dA.id,
                            author_department_name=dA.name, body="A 부서 회신"),
            AdvisoryComment(advisory_id=adv.id, author_name="B작성자", author_department_id=dB.id,
                            author_department_name=dB.name, body="B 부서 회신"),
            AdvisoryComment(advisory_id=adv.id, author_name="관리자", body="공통 공지",
                            is_admin=True),
        ])
        adv.board_published_at = datetime.now()
        db.commit()
        ids = dict(adv=adv.id, A=dA.id, B=dB.id, aA=aA.id, aB=aB.id)

    try:
        scoped_list = client.get("/api/v1/board/advisories",
                                 params={"department_id": ids["A"], "exclude_done": "false"}).json()["items"]
        scoped_row = next(x for x in scoped_list if x["doc_no"] == "SCOPE-1")
        assert scoped_row["comment_count"] == 2
        assert scoped_row["affected_departments"][0]["name"] == "스코프부서A"
        assert "스코프부서B" not in str(scoped_row)

        detail = client.get(f"/api/v1/board/advisories/{ids['adv']}",
                            params={"department_id": ids["A"]}).json()
        assert detail["advisory"]["affected_dept_count"] == 1
        assert detail["advisory"]["affected_departments"][0]["name"] == "스코프부서A"
        assert detail["advisory"]["affected_asset_count"] == 1
        assert detail["advisory"]["affected_products"] == ["Chrome"]
        assert [m["department"] for m in detail["matches"]] == ["스코프부서A"]
        assert detail["matches"][0]["asset_no"] == "SCOPE-A1"
        assert {c["cve_id_text"] for c in detail["cves"]} == {"CVE-2026-71001"}
        assert detail["progress"]["total"] == 1
        assert detail["progress"]["none"] == 1
        assert {c["author_name"] for c in detail["comments"]} == {"A작성자", "관리자"}

        text = str(detail)
        assert "스코프부서B" not in text
        assert "SCOPE-B1" not in text
        assert "B담당" not in text
        assert "B 부서 회신" not in text
    finally:
        with SessionLocal() as db:
            db.execute(delete(AdvisoryComment).where(AdvisoryComment.advisory_id == ids["adv"]))
            db.execute(delete(Notification).where(Notification.advisory_id == ids["adv"]))
            db.execute(delete(Match).where(Match.advisory_id == ids["adv"]))
            db.execute(delete(AdvisoryCve).where(AdvisoryCve.advisory_id == ids["adv"]))
            db.execute(delete(Advisory).where(Advisory.id == ids["adv"]))
            db.execute(delete(Asset).where(Asset.id.in_([ids["aA"], ids["aB"]])))
            db.execute(delete(Department).where(Department.id.in_([ids["A"], ids["B"]])))
            db.commit()


def test_board_pdf_view(client):
    """게시판에서 원본 PDF 열람 — 공개 시 200(application/pdf), 미공개 시 404."""
    import os
    from sqlalchemy import delete

    from app.config import UPLOAD_DIR
    from app.seed import _minimal_pdf

    pdf = _minimal_pdf(["Board PDF view test"])
    path = UPLOAD_DIR / "test-board-view.pdf"
    path.write_bytes(pdf)
    with SessionLocal() as db:
        adv = Advisory(doc_no="PDF-1", title="PDF 열람 테스트", file_path=str(path),
                       status=enums.AdvisoryStatus.EXTRACTED)
        db.add(adv)
        db.commit()
        aid = adv.id
    try:
        # 미공개 → 404
        assert client.get(f"/api/v1/board/advisories/{aid}/file").status_code == 404
        # 공개 → 200 PDF
        client.post(f"/api/v1/advisories/{aid}/board")
        r = client.get(f"/api/v1/board/advisories/{aid}/file")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert r.content[:5] == b"%PDF-"
    finally:
        with SessionLocal() as db:
            db.execute(delete(Advisory).where(Advisory.id == aid))
            db.commit()
        os.path.exists(path) and os.remove(path)


def test_delete_comment(client, fixture_ids):
    aid, _ = fixture_ids
    client.post(f"/api/v1/advisories/{aid}/board")
    cid = client.post(f"/api/v1/board/advisories/{aid}/comments",
                      json={"author_name": "을", "body": "삭제될 댓글"}).json()["comment"]["id"]
    assert client.delete(f"/api/v1/board/comments/{cid}").status_code == 204
    assert client.get(f"/api/v1/board/advisories/{aid}").json()["comments"] == []
