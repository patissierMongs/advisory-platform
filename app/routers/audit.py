"""활동 기록 — 감사 로그 조회(업로드·추출·피드·매칭·발송·회신·가져오기 전체 이력).

기록은 audit.record() 가 모든 변경에 남긴다(§3.10). 본 라우터는 그 기록을 사람이 읽을
형태로 조회하고, 권고문 관련 항목은 원문 PDF 로 바로 연결할 수 있게 advisory 정보를 덧붙인다.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Advisory, AppUser, AuditLog
from ..serializers import _d

router = APIRouter(prefix="/api/v1", tags=["audit"])

ACTION_KO: dict[str, str] = {
    "ADVISORY_UPLOAD": "권고문 업로드",
    "ADVISORY_EXTRACT": "CVE 추출",
    "ADVISORY_MATCH": "자산 매칭",
    "MATCH_EXCLUDE": "오탐 제외",
    "CVE_ADD_MANUAL": "CVE 수동 추가",
    "CVE_DELETE_MANUAL": "CVE 삭제",
    "CVE_FEED_VALIDATE": "CVE 피드 검증",
    "CVE_FEED_APPLY": "CVE 피드 적용",
    "ASSET_IMPORT_COMMIT": "자산대장 가져오기",
    "NOTIFY_SEND": "권고 발송",
    "NOTIFY_ACK": "조치 회신",
    "NOTIFY_EVIDENCE": "증빙 등록",
    "NOTIFY_REMIND": "미회신 리마인드",
    "BOARD_POST": "게시판 게시",
}


@router.get("/audit")
def list_audit(
    entity_type: str | None = None,
    action: str | None = None,
    page: int = 1,
    size: int = Query(50, le=200),
    db: Session = Depends(get_db),
):
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc(), AuditLog.id.desc())
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.limit(size).offset((page - 1) * size)).all()

    # 행위자·권고문 라벨을 일괄 조회(N+1 회피).
    actor_ids = {r.actor_id for r in rows if r.actor_id}
    actors = {u.id: u.display_name for u in db.scalars(
        select(AppUser).where(AppUser.id.in_(actor_ids)))} if actor_ids else {}
    adv_ids = {r.entity_id for r in rows if r.entity_type == "advisory" and r.entity_id}
    advs = {a.id: a for a in db.scalars(
        select(Advisory).where(Advisory.id.in_(adv_ids)))} if adv_ids else {}

    items = []
    for r in rows:
        adv = advs.get(r.entity_id) if r.entity_type == "advisory" else None
        items.append({
            "id": r.id,
            "created_at": _d(r.created_at),
            "action": r.action,
            "action_ko": ACTION_KO.get(r.action, r.action),
            "actor": actors.get(r.actor_id) or "시스템",
            "entity_type": r.entity_type,
            "entity_id": r.entity_id,
            "advisory_id": adv.id if adv else None,
            "advisory_title": adv.title if adv else None,
            "has_pdf": bool(adv and adv.file_path),
            "detail": r.detail,
            "ip": r.ip,
        })
    return {"total": total, "items": items}
