"""부서 알림 — 미리보기/발송/이력/회신 (명세서 §5.5, §4.7). 멱등성+게이트."""
from __future__ import annotations

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums
from ..auth import require_admin
from ..audit import record
from ..config import DATA_DIR, secure_dir, secure_write_bytes, settings
from ..core import notify, remediation
from ..core.files import check_evidence_upload, evidence_response
from ..db import get_db
from ..deps import get_actor_id
from ..models import Advisory, Department, Match, Notification
from ..schemas import AckPatch, NotifyRequest, NotifyTestRequest
from ..serializers import notification_item

EVIDENCE_DIR = secure_dir(DATA_DIR / "evidence")

router = APIRouter(prefix="/api/v1", tags=["notifications"],
                   dependencies=[Depends(require_admin)])  # 관리자 전용 — 라우터 전체 게이트


def _default_channels() -> list[enums.NotifyChannel]:
    channels = [enums.NotifyChannel.MAIL, enums.NotifyChannel.WEB_UI]
    if enums.NotifyChannel.MESSENGER not in channels and notify.settings.MESSENGER_ENABLED:
        channels.insert(0, enums.NotifyChannel.MESSENGER)
    return channels


def _active_matches(db: Session, advisory_id: int) -> list[Match]:
    return db.scalars(
        select(Match).where(Match.advisory_id == advisory_id, Match.status == enums.MatchStatus.MATCHED)
    ).all()


@router.get("/advisories/{advisory_id}/notification-preview")
def preview(advisory_id: int, db: Session = Depends(get_db)):
    adv = db.get(Advisory, advisory_id)
    if not adv:
        raise HTTPException(404, "권고문 없음")
    groups = notify.group_by_department(_active_matches(db, advisory_id))
    sent_keys = {
        n.department_id
        for n in db.scalars(select(Notification).where(
            Notification.advisory_id == advisory_id,
            Notification.status.in_([enums.NotificationStatus.SENT, enums.NotificationStatus.ACKED]),
        ))
    }
    out = []
    for dept_id, matches in groups.items():
        dept = db.get(Department, dept_id)
        cves = list(dict.fromkeys(m.advisory_cve.cve_id_text for m in matches))
        out.append({
            "department_id": dept_id,
            "department": dept.name if dept else str(dept_id),
            "asset_count": len(matches),
            "owners": ", ".join(dict.fromkeys(
                m.asset.owner_name for m in matches if m.asset.owner_name and m.asset.owner_name != "자동배포"
            )) or "시스템",
            "issue_count": len(cves),
            "cve_list": ", ".join(cves),
            "message": notify.build_message(adv, dept.name if dept else str(dept_id), matches),
            "default_channels": [c.value for c in _default_channels()],
            "sent": dept_id in sent_keys,
        })
    return {"departments": out, "total_departments": len(out),
            "sent_count": len(sent_keys & set(groups.keys()))}


@router.post("/advisories/{advisory_id}/notifications")
def send(advisory_id: int, body: NotifyRequest, request: Request, db: Session = Depends(get_db)):
    adv = db.get(Advisory, advisory_id)
    if not adv:
        raise HTTPException(404, "권고문 없음")

    groups = notify.group_by_department(_active_matches(db, advisory_id))
    if not groups:
        raise HTTPException(409, detail={"code": "NO_ACTIVE_MATCH", "message": "발송할 활성 매칭이 없습니다."})

    # 발송 대상 결정: all=true → 전 부서, 아니면 지정 부서.
    targets: dict[int, list[str]] = {}
    if body.all:
        common = [c.value for c in (body.channels or _default_channels())]
        targets = {dept_id: common for dept_id in groups}
    else:
        for d in (body.departments or []):
            if d.department_id in groups:
                targets[d.department_id] = [c.value for c in d.channels]
    if not targets:
        raise HTTPException(400, "발송 대상 부서가 없습니다.")

    adv.status = enums.AdvisoryStatus.NOTIFYING
    results = []
    actor = get_actor_id(db)
    for dept_id, channels in targets.items():
        matches = groups[dept_id]
        dept = db.get(Department, dept_id)
        asset_ids = sorted({m.asset_id for m in matches})
        key = notify.idempotency_key(advisory_id, dept_id, asset_ids)

        # (권고문, 부서)당 유효 통보는 1행 — 자산 구성이 바뀐 재발송은 행을 재사용해 갱신한다.
        # (행이 누적되면 이력·조치율이 부서 단위로 이중 계상되고 옛 행이 리마인드 대상에 남는다.)
        existing = db.scalar(
            select(Notification)
            .where(Notification.advisory_id == advisory_id, Notification.department_id == dept_id)
            .order_by(Notification.id.desc()).limit(1))
        if existing and existing.idempotency_key == key \
                and existing.status in (enums.NotificationStatus.SENT, enums.NotificationStatus.ACKED):
            results.append({
                "department_id": dept_id,
                "status": "SENT",
                "notification_id": existing.id,
                "idempotent": True,
                "delivery_results": [
                    {"channel": ch, "ok": True, "info": "idempotent"}
                    for ch in (existing.channels or [])
                ],
            })
            continue

        body_text = notify.build_message(adv, dept.name if dept else str(dept_id), matches)
        outcome = notify.dispatch(channels, dept.name if dept else "", dept.messenger_id if dept else None,
                                  dept.email if dept else None, body_text)
        n = existing or Notification(advisory_id=advisory_id, department_id=dept_id, idempotency_key=key)
        if existing is not None and existing.idempotency_key != key:
            # 자산 구성이 바뀐 재통보 — 이전 회신은 새 구성에 대한 확인이 아니므로 초기화.
            n.idempotency_key = key
            n.ack_status = enums.AckStatus.NONE
            n.ack_note = None
            n.ack_by = None
            n.ack_updated_at = None
            n.reminded_at = None
            n.reminder_count = 0
        n.channels = channels
        n.message_body = body_text
        n.asset_ids = asset_ids
        n.status = enums.NotificationStatus.SENT if outcome["ok"] else enums.NotificationStatus.FAILED
        n.sent_at = datetime.now(timezone.utc)
        n.sent_by = actor
        if not existing:
            db.add(n)
        db.flush()
        record(db, action="NOTIFY_SEND", actor_id=actor, entity_type="notification", entity_id=n.id,
               detail={"department_id": dept_id, "channels": channels, "result": outcome}, request=request)
        results.append({
            "department_id": dept_id,
            "status": n.status.value,
            "notification_id": n.id,
            "delivery_results": outcome["results"],
        })

    # 전 부서 발송 완료 시 COMPLETED.
    sent_depts = {
        n.department_id for n in db.scalars(select(Notification).where(
            Notification.advisory_id == advisory_id,
            Notification.status.in_([enums.NotificationStatus.SENT, enums.NotificationStatus.ACKED]),
        ))
    }
    if set(groups.keys()).issubset(sent_depts):
        adv.status = enums.AdvisoryStatus.COMPLETED
    db.commit()
    return {"results": results}


@router.get("/notify/status")
def notify_status():
    return notify.smtp_status()


@router.post("/notify/test")
def notify_test(body: NotifyTestRequest):
    return notify.send_test_mail(body.to.strip())


@router.get("/notifications")
def history(db: Session = Depends(get_db)):
    rows = db.scalars(select(Notification).order_by(Notification.sent_at.desc().nullslast(),
                                                    Notification.id.desc())).all()
    return {"items": [notification_item(n) for n in rows]}


@router.patch("/notifications/{notification_id}/ack")
def ack(notification_id: int, body: AckPatch, request: Request, db: Session = Depends(get_db)):
    """부서 조치 회신 갱신 (완료/진행중/불가 + 코멘트). 불가는 사유 필수."""
    n = db.get(Notification, notification_id)
    if not n:
        raise HTTPException(404, "발송 내역 없음")
    new = enums.AckStatus(body.ack_status)
    if new == enums.AckStatus.UNABLE and not (body.note or "").strip():
        raise HTTPException(400, "조치불가는 사유(note)가 필요합니다.")
    # 부서 단위 선언 → 해당 부서 자산 매칭에도 전파(게시판 자산 표시와 정합).
    synced_assets = remediation.apply_department_ack(db, n, new, body.note, body.by)
    db.flush()
    record(db, action="NOTIFY_ACK", actor_id=get_actor_id(db), entity_type="notification",
           entity_id=n.id, detail={"ack": new.value, "note": body.note,
                                   "assets_synced": synced_assets}, request=request)
    db.commit()
    return notification_item(n)


@router.post("/notifications/{notification_id}/evidence")
async def upload_evidence(notification_id: int, request: Request,
                          file: UploadFile = File(...), db: Session = Depends(get_db)):
    """조치 증빙 파일 업로드(§★★★★★) — 관리자 전용이라 재업로드(교체)를 허용한다.

    공개 게시판 쪽(board.upload_comment_evidence)은 무인증이라 교체를 409 로 막지만,
    여기는 인증된 관리자가 잘못 올린 파일을 바로잡는 정상 동선이다.
    """
    import os

    n = db.get(Notification, notification_id)
    if not n:
        raise HTTPException(404, "발송 내역 없음")
    content = await file.read()
    # 크기 검사가 형식 검사보다 먼저 — 거대한 파일은 형식과 무관하게 413.
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(413, f"파일 크기 초과(최대 {settings.MAX_UPLOAD_MB}MB)")
    display_name = check_evidence_upload(file.filename, content)
    previous = n.ack_evidence_path
    # 난수 접미사로 디스크상 덮어쓰기를 없앤다(동시 업로드 충돌·선점 방지).
    path = EVIDENCE_DIR / f"notif{notification_id}_{secrets.token_hex(8)}_{display_name}"
    secure_write_bytes(path, content, exclusive=True)
    n.ack_evidence_path = str(path)
    # 표시명도 안전화된 값을 저장한다 — 원본명을 그대로 두면 Content-Disposition 헤더와
    # 화면 양쪽에서 매번 정제에 의존하게 된다(게시판 쪽과도 불일치였다).
    n.ack_evidence_name = display_name
    if previous and previous != str(path):
        try:
            os.unlink(previous)
        except OSError:
            pass  # 이미 없거나 잠김 — 교체 자체를 실패시킬 이유는 없다
    db.flush()
    record(db, action="NOTIFY_EVIDENCE", actor_id=get_actor_id(db), entity_type="notification",
           entity_id=n.id, detail={"file": display_name}, request=request)
    db.commit()
    return notification_item(n)


@router.get("/notifications/{notification_id}/evidence")
def get_evidence(notification_id: int, db: Session = Depends(get_db)):
    """조치 증빙 파일 열람 — 안전 타입만 inline, 그 외 첨부(파일명 헤더 안전화). 첨부 없으면 404."""
    import os

    n = db.get(Notification, notification_id)
    if not n or not n.ack_evidence_path or not os.path.exists(n.ack_evidence_path):
        raise HTTPException(404, "증빙 파일이 없습니다")
    return evidence_response(n.ack_evidence_path, n.ack_evidence_name)
