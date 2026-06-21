"""게시판 자산별 조치 회신 — 자산 단위 진행률 · 부서 불일치 차단 · 발송이력 동기화 · 필터 스코핑."""
from __future__ import annotations

from datetime import datetime

import pytest

from app import enums
from app.db import SessionLocal
from app.models import (
    Advisory, AdvisoryComment, AdvisoryCve, Asset, Department, Match, Notification,
)


@pytest.fixture()
def ack_ids():
    """부서 2 + 부서별 자산/매칭 1건씩 + 공개 권고문. 테스트 후 정리."""
    with SessionLocal() as db:
        dA = Department(name="조치부서A", is_active=True)
        dB = Department(name="조치부서B", is_active=True)
        adv = Advisory(doc_no="AACK-1", title="자산조치 테스트 권고문",
                       status=enums.AdvisoryStatus.MATCHED)
        db.add_all([dA, dB, adv])
        db.commit()
        aid, didA, didB = adv.id, dA.id, dB.id
        asA = Asset(asset_no="AACK-A1", department_id=didA, product_key="google_chrome",
                    product_raw="Google Chrome", version_raw="120", owner_name="갑담당",
                    status=enums.AssetStatus.NORMAL)
        asB = Asset(asset_no="AACK-B1", department_id=didB, product_key="google_chrome",
                    product_raw="Google Chrome", version_raw="121", owner_name="을담당",
                    status=enums.AssetStatus.NORMAL)
        ac = AdvisoryCve(advisory_id=aid, cve_id_text="CVE-2026-30012",
                         lookup_status=enums.LookupStatus.FOUND)
        db.add_all([asA, asB, ac])
        db.commit()
        mA = Match(advisory_id=aid, advisory_cve_id=ac.id, asset_id=asA.id,
                   status=enums.MatchStatus.MATCHED)
        mB = Match(advisory_id=aid, advisory_cve_id=ac.id, asset_id=asB.id,
                   status=enums.MatchStatus.MATCHED)
        db.add_all([mA, mB])
        db.get(Advisory, aid).board_published_at = datetime.now()
        db.commit()
        ids = dict(aid=aid, didA=didA, didB=didB, asA=asA.id, asB=asB.id, mA=mA.id, mB=mB.id)
    yield ids
    with SessionLocal() as db:
        from sqlalchemy import delete
        db.execute(delete(AdvisoryComment).where(AdvisoryComment.advisory_id == ids["aid"]))
        db.execute(delete(Notification).where(Notification.advisory_id == ids["aid"]))
        db.execute(delete(Match).where(Match.advisory_id == ids["aid"]))
        db.execute(delete(AdvisoryCve).where(AdvisoryCve.advisory_id == ids["aid"]))
        db.execute(delete(Advisory).where(Advisory.id == ids["aid"]))
        db.execute(delete(Asset).where(Asset.id.in_([ids["asA"], ids["asB"]])))
        db.execute(delete(Department).where(Department.id.in_([ids["didA"], ids["didB"]])))
        db.commit()


def test_asset_ack_marks_done_and_asset_progress(client, ack_ids):
    aid = ack_ids["aid"]
    r = client.post(f"/api/v1/board/advisories/{aid}/asset-ack",
                    json={"author_name": "갑담당", "department_id": ack_ids["didA"],
                          "ack_status": "DONE", "match_ids": [ack_ids["mA"]]})
    assert r.status_code == 200
    body = r.json()
    assert body["updated"] == 1
    assert body["progress"]["total"] == 2 and body["progress"]["done"] == 1
    assert body["progress"]["done_rate"] == 50

    detail = client.get(f"/api/v1/board/advisories/{aid}").json()
    mA = next(m for m in detail["matches"] if m["id"] == ack_ids["mA"])
    mB = next(m for m in detail["matches"] if m["id"] == ack_ids["mB"])
    assert mA["ack_status"] == "DONE" and mA["ack_by"] == "갑담당"
    assert mB["ack_status"] == "NONE"


def test_asset_ack_rejects_other_department(client, ack_ids):
    """부서 A 담당자가 부서 B 자산을 처리하려 하면 409(DEPT_MISMATCH)."""
    aid = ack_ids["aid"]
    r = client.post(f"/api/v1/board/advisories/{aid}/asset-ack",
                    json={"author_name": "갑담당", "department_id": ack_ids["didA"],
                          "ack_status": "DONE", "match_ids": [ack_ids["mB"]]})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "DEPT_MISMATCH"
    # 거부됐으므로 B 자산 상태는 그대로.
    with SessionLocal() as db:
        assert db.get(Match, ack_ids["mB"]).ack_status == enums.AckStatus.NONE


def test_asset_ack_syncs_department_notification_when_all_done(client, ack_ids):
    """부서 전체 자산이 DONE 이면 해당 부서 발송이력 ack 도 DONE 으로 동기화."""
    aid, didA = ack_ids["aid"], ack_ids["didA"]
    with SessionLocal() as db:
        n = Notification(advisory_id=aid, department_id=didA, channels=[], asset_ids=[],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE)
        db.add(n)
        db.commit()
        nid = n.id
    # 부서 A 자산은 mA 하나뿐 → DONE 처리하면 부서 전체 완료.
    r = client.post(f"/api/v1/board/advisories/{aid}/asset-ack",
                    json={"author_name": "갑담당", "department_id": didA,
                          "ack_status": "DONE", "match_ids": [ack_ids["mA"]]})
    assert r.status_code == 200 and r.json()["ack_synced_notification"] == nid
    with SessionLocal() as db:
        n = db.get(Notification, nid)
        assert n.ack_status == enums.AckStatus.DONE
        assert n.status == enums.NotificationStatus.ACKED


def test_board_detail_filter_scopes_to_searcher(client, ack_ids):
    """필터(q) 적용 시 상세는 검색 대상 자산/댓글만 노출(다른 부서·사람 숨김)."""
    aid = ack_ids["aid"]
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "갑담당", "department_id": ack_ids["didA"], "body": "A부서 회신"})
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "을담당", "department_id": ack_ids["didB"], "body": "B부서 회신"})

    # 검색 없음 → 둘 다 노출.
    full = client.get(f"/api/v1/board/advisories/{aid}").json()
    assert full["scoped"] is False and len(full["matches"]) == 2
    assert len(full["comments"]) == 2

    # '갑담당' 검색 → A 자산/댓글만, B는 숨김.
    scoped = client.get(f"/api/v1/board/advisories/{aid}", params={"q": "갑담당"}).json()
    assert scoped["scoped"] is True
    assert [m["asset_no"] for m in scoped["matches"]] == ["AACK-A1"]
    authors = [c["author_name"] for c in scoped["comments"]]
    assert "갑담당" in authors and "을담당" not in authors
    # 상단 영향 요약도 본인 부서만(타부서 미노출).
    assert scoped["advisory"]["affected_dept_count"] == 1
    assert [dd["name"] for dd in scoped["advisory"]["affected_departments"]] == ["조치부서A"]


def test_board_detail_title_search_shows_all(client, ack_ids):
    """제목/문서번호 검색(주제 검색)은 스코핑하지 않고 전체 노출."""
    aid = ack_ids["aid"]
    res = client.get(f"/api/v1/board/advisories/{aid}", params={"q": "자산조치"}).json()
    assert res["scoped"] is False and len(res["matches"]) == 2


# ── 댓글 + 체크 자산(match_ids) 동기화(자산 조치 회신을 댓글로 대체) ──
def test_comment_with_match_ids_acks_checked_assets(client, ack_ids):
    """댓글에 조치상태+부서+체크자산(match_ids) → 댓글 등록 + 해당 자산 ack 반영(이름 무관)."""
    aid = ack_ids["aid"]
    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"author_name": "아무개", "department_id": ack_ids["didA"],
                          "body": "패치 완료했습니다", "ack_status": "DONE",
                          "match_ids": [ack_ids["mA"]]})
    assert r.status_code == 201
    assert r.json()["assets_updated"] == 1

    detail = client.get(f"/api/v1/board/advisories/{aid}").json()
    mA = next(m for m in detail["matches"] if m["id"] == ack_ids["mA"])
    mB = next(m for m in detail["matches"] if m["id"] == ack_ids["mB"])
    assert mA["ack_status"] == "DONE" and mA["ack_by"] == "아무개"   # 이름 무관, 부서만 일치
    assert mB["ack_status"] == "NONE"


def test_comment_with_match_ids_rejects_other_department(client, ack_ids):
    """댓글로 다른 부서 자산을 처리하려 하면 409(DEPT_MISMATCH), 자산 상태·댓글 불변."""
    aid = ack_ids["aid"]
    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"author_name": "갑담당", "department_id": ack_ids["didA"],
                          "body": "잘못 체크", "ack_status": "DONE",
                          "match_ids": [ack_ids["mB"]]})
    assert r.status_code == 409
    assert r.json()["detail"]["code"] == "DEPT_MISMATCH"
    with SessionLocal() as db:
        assert db.get(Match, ack_ids["mB"]).ack_status == enums.AckStatus.NONE
    # 거부 시 댓글도 저장되지 않음.
    detail = client.get(f"/api/v1/board/advisories/{aid}").json()
    assert detail["comments"] == []


def test_board_detail_department_id_scopes(client, ack_ids):
    """department_id('내 부서') 필터 → 해당 부서 자산/댓글만, 타부서 숨김(관리자 댓글은 노출)."""
    aid = ack_ids["aid"]
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "갑담당", "department_id": ack_ids["didA"], "body": "A 회신"})
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "을담당", "department_id": ack_ids["didB"], "body": "B 회신"})
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "관리자", "body": "공지", "is_admin": True})

    scoped = client.get(f"/api/v1/board/advisories/{aid}",
                        params={"department_id": ack_ids["didA"]}).json()
    assert scoped["scoped"] is True
    assert [m["asset_no"] for m in scoped["matches"]] == ["AACK-A1"]
    authors = [c["author_name"] for c in scoped["comments"]]
    assert "갑담당" in authors and "관리자" in authors and "을담당" not in authors
    assert scoped["advisory"]["affected_dept_count"] == 1


def test_board_list_row_scoped_to_department(client, ack_ids):
    """'내 부서' 필터 시 목록 행의 영향요약·진행률·댓글수도 그 부서만(타부서 미노출) — Codex P2."""
    aid = ack_ids["aid"]
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "갑담당", "department_id": ack_ids["didA"], "body": "A"})
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "을담당", "department_id": ack_ids["didB"], "body": "B"})
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "관리자", "body": "공지", "is_admin": True})

    res = client.get("/api/v1/board/advisories",
                     params={"department_id": ack_ids["didA"], "exclude_done": "false"}).json()
    row = next(it for it in res["items"] if it["id"] == aid)
    assert row["affected_dept_count"] == 1
    assert [d["name"] for d in row["affected_departments"]] == ["조치부서A"]
    assert row["affected_asset_count"] == 1
    assert row["progress"]["total"] == 1                 # B부서 자산(1) 미포함
    assert row["comment_count"] == 2                     # A부서(1)+관리자(1), B부서 제외


def test_comment_done_partial_assets_keeps_department_open(client):
    """부서 자산 2개 중 1개만 체크 + DONE 댓글 → 부서 발송 ack 종결 안 됨(진행중) — Codex P1."""
    with SessionLocal() as db:
        d = Department(name="부분조치부서", is_active=True)
        adv = Advisory(doc_no="PART-1", title="부분조치 테스트",
                       status=enums.AdvisoryStatus.MATCHED, board_published_at=datetime.now())
        db.add_all([d, adv])
        db.commit()
        aid, did = adv.id, d.id
        a1 = Asset(asset_no="PART-A1", department_id=did, product_key="google_chrome",
                   product_raw="Chrome", version_raw="120", status=enums.AssetStatus.NORMAL)
        a2 = Asset(asset_no="PART-A2", department_id=did, product_key="google_chrome",
                   product_raw="Chrome", version_raw="121", status=enums.AssetStatus.NORMAL)
        ac = AdvisoryCve(advisory_id=aid, cve_id_text="CVE-2026-40001",
                         lookup_status=enums.LookupStatus.FOUND)
        db.add_all([a1, a2, ac])
        db.commit()
        m1 = Match(advisory_id=aid, advisory_cve_id=ac.id, asset_id=a1.id,
                   status=enums.MatchStatus.MATCHED)
        m2 = Match(advisory_id=aid, advisory_cve_id=ac.id, asset_id=a2.id,
                   status=enums.MatchStatus.MATCHED)
        n = Notification(advisory_id=aid, department_id=did, channels=[], asset_ids=[],
                         status=enums.NotificationStatus.SENT, ack_status=enums.AckStatus.NONE)
        db.add_all([m1, m2, n])
        db.commit()
        ids = dict(aid=aid, did=did, m1=m1.id, m2=m2.id, n=n.id, a1=a1.id, a2=a2.id)
    try:
        client.post(f"/api/v1/board/advisories/{ids['aid']}/comments",
                    json={"author_name": "갑", "department_id": ids["did"], "body": "1대 완료",
                          "ack_status": "DONE", "match_ids": [ids["m1"]]})
        with SessionLocal() as db:
            assert db.get(Match, ids["m1"]).ack_status == enums.AckStatus.DONE
            assert db.get(Match, ids["m2"]).ack_status == enums.AckStatus.NONE
            n = db.get(Notification, ids["n"])
            assert n.ack_status == enums.AckStatus.IN_PROGRESS        # 부서 미종결
            assert n.status != enums.NotificationStatus.ACKED
        # 나머지 자산까지 DONE → 부서 종결.
        client.post(f"/api/v1/board/advisories/{ids['aid']}/comments",
                    json={"author_name": "갑", "department_id": ids["did"], "body": "나머지 완료",
                          "ack_status": "DONE", "match_ids": [ids["m2"]]})
        with SessionLocal() as db:
            n = db.get(Notification, ids["n"])
            assert n.ack_status == enums.AckStatus.DONE
            assert n.status == enums.NotificationStatus.ACKED
    finally:
        with SessionLocal() as db:
            from sqlalchemy import delete
            db.execute(delete(AdvisoryComment).where(AdvisoryComment.advisory_id == ids["aid"]))
            db.execute(delete(Notification).where(Notification.advisory_id == ids["aid"]))
            db.execute(delete(Match).where(Match.advisory_id == ids["aid"]))
            db.execute(delete(AdvisoryCve).where(AdvisoryCve.advisory_id == ids["aid"]))
            db.execute(delete(Asset).where(Asset.id.in_([ids["a1"], ids["a2"]])))
            db.execute(delete(Advisory).where(Advisory.id == ids["aid"]))
            db.execute(delete(Department).where(Department.id == ids["did"]))
            db.commit()
