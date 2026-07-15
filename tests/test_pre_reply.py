"""발송 전 선(先)회신(§선처리) — 게시판 선처리 회신이 발송 이력에 보이고, 발송 후에도 보존."""
from __future__ import annotations

import io
import uuid


def _setup_published_with_match(client):
    """게시판 공개 권고문 + 부서 + 매칭 자산 1대 (발송은 아직 안 함)."""
    from datetime import datetime, timezone

    from app import enums
    from app.db import SessionLocal
    from app.models import Advisory, AdvisoryCve, Asset, Cve, Department, Match

    pdf = b"%PDF-1.4 " + uuid.uuid4().hex.encode()
    r = client.post("/api/v1/advisories",
                    files={"file": ("pre-reply.pdf", io.BytesIO(pdf), "application/pdf")},
                    data={"source_org": "KISA"})
    aid = r.json()["id"]
    with SessionLocal() as db:
        dept = Department(name=f"선회신부서{aid}", email="d@x")
        db.add(dept)
        db.flush()
        cve = Cve(cve_id=f"CVE-2099-{9000 + aid}", product_key="google_chrome",
                  product_name="Google Chrome", affected_versions={"lt": "999"},
                  severity=enums.Severity.HIGH)
        db.add(cve)
        db.flush()
        adv = db.get(Advisory, aid)
        adv.board_published_at = datetime.now(timezone.utc)
        adv.status = enums.AdvisoryStatus.MATCHED
        ac = AdvisoryCve(advisory_id=aid, cve_id_text=cve.cve_id, cve_ref_id=cve.id,
                         lookup_status=enums.LookupStatus.FOUND)
        db.add(ac)
        db.flush()
        asset = Asset(asset_no=f"PR-{aid}", department_id=dept.id,
                      product_key="google_chrome", version_raw="120", version_norm="120")
        db.add(asset)
        db.flush()
        db.add(Match(advisory_id=aid, advisory_cve_id=ac.id, asset_id=asset.id))
        db.flush()
        ids = (aid, dept.id)
        db.commit()
    return ids


def test_pre_reply_creates_pending_row_visible_in_history(client):
    aid, did = _setup_published_with_match(client)
    # 발송 '전'에 담당자가 게시판에서 조치완료 회신 — 이전에는 조용히 유실되던 케이스.
    r = client.post(f"/api/v1/board/advisories/{aid}/comments",
                    json={"author_name": "선처리담당", "department_id": did,
                          "body": "발송 전에 이미 패치 완료했습니다", "ack_status": "DONE"})
    assert r.status_code == 201
    assert r.json()["ack_synced_notification"] is not None   # 더 이상 None 아님

    roll = client.get("/api/v1/history/advisories").json()["items"]
    adv = next(a for a in roll if a["id"] == aid)             # 발송 이력에 나타난다
    d = adv["departments"][0]
    assert d["ack_status"] == "DONE"
    assert d["ack_by"] == "선처리담당"
    assert d["status"] == "PENDING"                           # 미발송(선회신) 표식


def test_pre_reply_ack_survives_actual_send(client):
    aid, did = _setup_published_with_match(client)
    client.post(f"/api/v1/board/advisories/{aid}/comments",
                json={"author_name": "선처리담당", "department_id": did,
                      "body": "선조치 완료", "ack_status": "DONE"})
    # 이후 실제 발송 — 선회신 행이 재사용·승격되고 ack 는 초기화되지 않아야 한다.
    r = client.post(f"/api/v1/advisories/{aid}/notifications",
                    json={"all": True, "channels": ["WEB_UI"]})
    assert r.status_code == 200, r.text
    rows = client.get("/api/v1/notifications").json()["items"]
    mine = [n for n in rows if n["advisory_id"] == aid and n["department_id"] == did]
    assert len(mine) == 1                                     # 행 중복 없음(재사용)
    assert mine[0]["ack_status"] == "DONE"                    # 선회신 보존
    assert mine[0]["ack_by"] == "선처리담당"
