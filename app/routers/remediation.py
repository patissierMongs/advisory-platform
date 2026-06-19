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
from ..schemas import GroupwareAckWebhook

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
    targets = db.scalars(select(Notification).where(
        Notification.advisory_id == advisory_id,
        Notification.ack_status.in_([enums.AckStatus.NONE, enums.AckStatus.IN_PROGRESS]),
    )).all()
    only = set(body.get("department_ids") or [])
    if only:
        targets = [n for n in targets if n.department_id in only]
    if not targets:
        return {"reminded": 0, "results": []}

    results = []
    for n in targets:
        dept = db.get(Department, n.department_id)
        msg = (f"[조치기한 임박 알림] {adv.title or ''}\n근거 {adv.doc_no or ''} · 기한 {adv.due_at or ''}"
               f"{f' (D{d_day:+d})' if d_day is not None else ''}\n"
               f"귀 부서 회신이 확인되지 않았습니다. 기한 내 조치 후 회신 바랍니다.")
        notify.dispatch(n.channels or ["MAIL"], dept.name if dept else "",
                        dept.messenger_id if dept else None, dept.email if dept else None, msg)
        n.reminded_at = datetime.now(timezone.utc)
        n.reminder_count = (n.reminder_count or 0) + 1
        results.append({"department_id": n.department_id, "department": dept.name if dept else None,
                        "reminder_count": n.reminder_count})
    db.flush()
    record(db, action="NOTIFY_REMIND", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=advisory_id, detail={"count": len(results)}, request=request)
    db.commit()
    return {"reminded": len(results), "results": results}


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


@router.post("/webhooks/groupware/ack")
def groupware_ack(payload: GroupwareAckWebhook, db: Session = Depends(get_db)):
    """그룹웨어 댓글 회신 → ack 동기화. (게시판 회신과 시스템 상태 연결)"""
    norm = groupware.parse_ack_webhook(payload.model_dump())
    if not norm:
        raise HTTPException(400, "해석할 수 없는 회신 payload")
    dept = db.scalar(select(Department).where(Department.name == norm["department"]))
    if not dept:
        raise HTTPException(404, f"부서 없음: {norm['department']}")
    # 가장 최근 미종료 알림을 갱신.
    n = db.scalar(select(Notification).where(
        Notification.department_id == dept.id,
        Notification.ack_status.notin_([enums.AckStatus.DONE, enums.AckStatus.UNABLE]),
    ).order_by(Notification.sent_at.desc()))
    if not n:
        raise HTTPException(404, "해당 부서의 미종료 발송 내역 없음")
    n.ack_status = enums.AckStatus(norm["ack_status"])
    n.ack_note = norm.get("note")
    n.ack_by = norm.get("by")
    n.ack_updated_at = datetime.now(timezone.utc)
    if n.ack_status == enums.AckStatus.DONE:
        n.status = enums.NotificationStatus.ACKED
    db.commit()
    return {"ok": True, "notification_id": n.id, "ack_status": n.ack_status.value}


# ── 오탐 제외 기억 (§★★★) ──
@router.get("/exclusion-rules")
def list_exclusions(db: Session = Depends(get_db)):
    return {"items": exclusions.list_rules(db)}
