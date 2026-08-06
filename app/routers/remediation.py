"""발송 후 단계 — 조치 진척/보고서/SLA/리마인드/게시판/오탐기억 (§★★★★★~★★★)."""
from __future__ import annotations

import io
from datetime import date, datetime, timezone

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..core import exclusions, groupware, notify, remediation, reports
from ..db import get_db
from ..deps import get_actor_id
from ..models import Advisory, Department, Notification

router = APIRouter(prefix="/api/v1", tags=["remediation"])


def _adv(db: Session, advisory_id: int) -> Advisory:
    adv = db.get(Advisory, advisory_id)
    if not adv:
        raise HTTPException(404, "권고문 없음")
    return adv


# ── 조치 진척 루프 (§★★★★★) ──
@router.get("/advisories/{advisory_id}/remediation")
def get_remediation(advisory_id: int, db: Session = Depends(get_db)):
    return remediation.advisory_remediation(db, _adv(db, advisory_id))


# ── 보고서 자동 생성 (§★★★★★) ──
@router.get("/advisories/{advisory_id}/report.xlsx")
def report_xlsx(advisory_id: int, db: Session = Depends(get_db)):
    adv = _adv(db, advisory_id)
    data = reports.build_excel(db, adv)
    fname = f"조치결과보고서_{adv.doc_no or adv.id}.xlsx"
    from urllib.parse import quote

    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{quote(fname)}"},
    )


@router.get("/advisories/{advisory_id}/report.html", response_class=HTMLResponse)
def report_html(advisory_id: int, db: Session = Depends(get_db)):
    """브라우저 인쇄(Ctrl+P)로 PDF 저장 가능한 한글 보고서."""
    return reports.build_html(db, _adv(db, advisory_id))


# ── SLA / 리마인드 (§★★★★) ──
@router.get("/reminders/due")
def reminders_due(within_days: int = 3, db: Session = Depends(get_db)):
    return {"items": remediation.due_reminders(db, within_days)}


@router.post("/advisories/{advisory_id}/remind")
def send_reminders(advisory_id: int, request: Request,
                   body: dict = Body(default={}), db: Session = Depends(get_db)):
    """미회신/진행중 부서에 리마인드 발송. body: {department_ids?:[...]}."""
    adv = _adv(db, advisory_id)
    d_day = (adv.due_at - date.today()).days if adv.due_at else None
    # D-표기 관례: 남은 3일 = D-3, 초과 3일 = D+3.
    d_label = None if d_day is None else ("D-DAY" if d_day == 0 else (f"D-{d_day}" if d_day > 0 else f"D+{-d_day}"))
    # 원발송 실패(FAILED) 부서는 '회신 미확인 리마인드' 대상이 아니라 재발송 대상.
    targets = db.scalars(select(Notification).where(
        Notification.advisory_id == advisory_id,
        Notification.ack_status.in_([enums.AckStatus.NONE, enums.AckStatus.IN_PROGRESS]),
        Notification.status != enums.NotificationStatus.FAILED,
    )).all()
    only = set(body.get("department_ids") or [])
    if only:
        targets = [n for n in targets if n.department_id in only]
    if not targets:
        return {"reminded": 0, "results": []}

    # 선택: 발송 문구 프리셋 본문(화면에서 플레이스홀더 치환 후 전달). 미지정 시 기본 문구.
    custom = (body.get("message") or "").strip() or None

    results = []
    for n in targets:
        dept = db.get(Department, n.department_id)
        msg = custom or (
            f"[조치기한 임박 알림] {adv.title or ''}\n근거 {adv.doc_no or ''} · 기한 {adv.due_at or ''}"
            f"{f' ({d_label})' if d_label else ''}\n"
            f"귀 부서 회신이 확인되지 않았습니다. 기한 내 조치 후 회신 바랍니다.")
        outcome = notify.dispatch(n.channels or ["MAIL"], dept.name if dept else "",
                                  dept.messenger_id if dept else None, dept.email if dept else None, msg)
        if outcome["ok"]:
            n.reminded_at = datetime.now(timezone.utc)
            n.reminder_count = (n.reminder_count or 0) + 1
        results.append({
            "department_id": n.department_id,
            "department": dept.name if dept else None,
            "status": "SENT" if outcome["ok"] else "FAILED",
            "reminder_count": n.reminder_count or 0,
            "delivery_results": outcome["results"],
        })
    db.flush()
    success_count = sum(1 for r in results if r["status"] == "SENT")
    record(db, action="NOTIFY_REMIND", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=advisory_id, detail={"count": success_count, "failed": len(results) - success_count}, request=request)
    db.commit()
    return {"reminded": success_count, "results": results}


# ── 수동 종결 (§운영 보완) ──
@router.post("/advisories/{advisory_id}/close")
def close_advisory(advisory_id: int, request: Request,
                   body: dict = Body(default={}), db: Session = Depends(get_db)):
    """권고문 수동 종결 — CVE 없는 일반 공지, 대상 자산 없음, 부분 발송 잔존 등
    자동 완료(전 부서 발송)에 도달할 수 없는 권고문을 관리자가 명시적으로 마감한다."""
    adv = _adv(db, advisory_id)
    if adv.status == enums.AdvisoryStatus.COMPLETED:
        return {"advisory_id": adv.id, "status": adv.status.value, "already_closed": True}
    prev = adv.status.value
    adv.status = enums.AdvisoryStatus.COMPLETED
    record(db, action="ADVISORY_CLOSE", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"from": prev, "reason": (body.get("reason") or "").strip() or None},
           request=request)
    db.commit()
    return {"advisory_id": adv.id, "status": adv.status.value, "from": prev}


# ── 그룹웨어 게시판 연동 (§★★★) ──
@router.post("/advisories/{advisory_id}/board")
def post_to_board(advisory_id: int, request: Request, db: Session = Depends(get_db)):
    adv = _adv(db, advisory_id)
    body = f"[보안권고문] {adv.title}\n문서번호 {adv.doc_no}\n조치기한 {adv.due_at}\n각 부서는 조치 후 댓글로 회신 바랍니다."
    post_id = groupware.post_board(adv.id, adv.doc_no or "", adv.title or "", body)
    adv.board_post_id = post_id
    # 내부 게시판(/board)에 공개 — 사내 누구나 보고 댓글 회신 가능.
    if adv.board_published_at is None:
        adv.board_published_at = datetime.now(timezone.utc)
    db.flush()
    record(db, action="BOARD_POST", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"post_id": post_id}, request=request)
    db.commit()
    return {"board_post_id": post_id, "board_published": True}


@router.post("/advisories/{advisory_id}/board-unpublish")
def unpublish_board(advisory_id: int, request: Request, db: Session = Depends(get_db)):
    """내부 게시판에서 권고문 내림(댓글은 보존). 관리자용."""
    adv = _adv(db, advisory_id)
    adv.board_published_at = None
    record(db, action="BOARD_UNPUBLISH", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail=None, request=request)
    db.commit()
    return {"board_published": False}


# ── 오탐 제외 기억 (§★★★) ──
@router.get("/exclusion-rules")
def list_exclusions(db: Session = Depends(get_db)):
    return {"items": exclusions.list_rules(db)}
