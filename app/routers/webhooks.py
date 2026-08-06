"""외부 시스템 수신 웹훅 — HMAC 서명 검증 (보안검토 H-4).

관리자 라우터와 분리한 이유: 이 엔드포인트는 사람이 아니라 그룹웨어 서버가 호출한다.
쿠키 세션 게이트를 걸 수 없으므로 공유 시크릿 기반 서명으로 대신 인증한다.

시크릿이 없으면 503 으로 닫는다(fail closed) — 미설정 상태에서 무인증으로 열려 있으면
누구나 임의 부서의 보안 조치를 '완료'로 위조할 수 있다.

호출 규약
    X-Advisory-Timestamp: <unix seconds>
    X-Advisory-Signature: sha256=<hex>
    서명 대상 = f"{timestamp}.".encode() + 요청 본문 원문(raw body)
"""
from __future__ import annotations

import hashlib
import hmac
import time

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..config import settings
from ..core import groupware, remediation
from ..db import get_db
from ..models import Advisory, Department, Notification
from ..schemas import GroupwareAckWebhook

# 리플레이 허용 창. 짧을수록 안전하지만 서버 간 시계 오차를 견뎌야 한다.
MAX_SKEW_SEC = 300


async def require_webhook_hmac(request: Request) -> None:
    """서명 검증 의존성.

    Starlette 가 body 를 캐시하므로 여기서 await request.body() 를 읽어도
    엔드포인트의 payload 파라미터 파싱에 지장이 없다(시그니처 무수정).
    """
    secret = settings.WEBHOOK_SECRET
    if not secret:
        raise HTTPException(503, detail={
            "code": "WEBHOOK_DISABLED",
            "message": "웹훅 시크릿이 설정되지 않아 비활성 상태입니다.",
        })

    ts = request.headers.get("x-advisory-timestamp") or ""
    sig = request.headers.get("x-advisory-signature") or ""
    invalid = HTTPException(401, detail={"code": "BAD_SIGNATURE",
                                         "message": "웹훅 서명 검증에 실패했습니다."})
    try:
        skew = abs(time.time() - int(ts))
    except ValueError:
        raise invalid from None
    if skew > MAX_SKEW_SEC:
        raise invalid

    raw = await request.body()
    expected = hmac.new(secret.encode("utf-8"), f"{ts}.".encode() + raw,
                        hashlib.sha256).hexdigest()
    if not sig.startswith("sha256=") or not hmac.compare_digest(sig[7:], expected):
        raise invalid


router = APIRouter(prefix="/api/v1", tags=["webhooks"],
                   dependencies=[Depends(require_webhook_hmac)])


@router.post("/webhooks/groupware/ack")
def groupware_ack(payload: GroupwareAckWebhook, request: Request, db: Session = Depends(get_db)):
    """그룹웨어 댓글 회신 → ack 동기화. (게시판 회신과 시스템 상태 연결)

    부서에 미종료 발송이 여러 권고문에 걸쳐 있으면 advisory_id/doc_no 로 대상을 특정해야 한다 —
    '가장 최근 것'을 임의로 고르면 엉뚱한 권고문이 종결될 수 있다.
    """
    norm = groupware.parse_ack_webhook(payload.model_dump())
    if not norm:
        raise HTTPException(400, "해석할 수 없는 회신 payload")
    dept = db.scalar(select(Department).where(Department.name == norm["department"]))
    if not dept:
        raise HTTPException(404, f"부서 없음: {norm['department']}")

    q = select(Notification).where(
        Notification.department_id == dept.id,
        Notification.ack_status.notin_([enums.AckStatus.DONE, enums.AckStatus.UNABLE]),
    )
    if payload.advisory_id is not None:
        q = q.where(Notification.advisory_id == payload.advisory_id)
    elif payload.doc_no:
        adv_ids = db.scalars(select(Advisory.id).where(Advisory.doc_no == payload.doc_no)).all()
        if not adv_ids:
            raise HTTPException(404, f"문서번호 없음: {payload.doc_no}")
        q = q.where(Notification.advisory_id.in_(adv_ids))
    candidates = db.scalars(q.order_by(Notification.sent_at.desc())).all()
    if not candidates:
        raise HTTPException(404, "해당 부서의 미종료 발송 내역 없음")
    open_advisories = {c.advisory_id for c in candidates}
    if len(open_advisories) > 1:
        raise HTTPException(409, detail={
            "code": "AMBIGUOUS_ADVISORY",
            "message": "해당 부서에 미종료 권고문이 여러 건입니다. advisory_id 또는 doc_no 로 지정하세요.",
            "candidates": sorted(open_advisories),
        })
    n = candidates[0]
    synced = remediation.apply_department_ack(
        db, n, enums.AckStatus(norm["ack_status"]), norm.get("note"), norm.get("by"))
    record(db, action="GROUPWARE_ACK", actor_id=None, entity_type="notification",
           entity_id=n.id, detail={"department": dept.name, "ack": norm["ack_status"],
                                   "assets_synced": synced}, request=request)
    db.commit()
    return {"ok": True, "notification_id": n.id, "ack_status": n.ack_status.value}
