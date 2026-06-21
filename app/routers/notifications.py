"""부서 알림 — 미리보기/발송/이력/회신 (명세서 §5.5, §4.7). 멱등성+게이트."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..config import DATA_DIR, settings
from ..core import notify
from ..core.files import safe_filename
from ..db import get_db
from ..deps import get_actor_id
from ..models import Advisory, Department, Match, Notification
from ..schemas import AckPatch, NotifyRequest, NotifyTestRequest
from ..serializers import notification_item

EVIDENCE_DIR = DATA_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)

router = APIRouter(prefix="/api/v1", tags=["notifications"])


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

        existing = db.scalar(select(Notification).where(Notification.idempotency_key == key))
        if existing and existing.status in (enums.NotificationStatus.SENT, enums.NotificationStatus.ACKED):
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
    n.ack_status = new
    if body.note is not None:
        n.ack_note = body.note
    if body.by is not None:
        n.ack_by = body.by
    n.ack_updated_at = datetime.now(timezone.utc)
    n.status = enums.NotificationStatus.ACKED if new == enums.AckStatus.DONE else n.status
    db.flush()
    record(db, action="NOTIFY_ACK", actor_id=get_actor_id(db), entity_type="notification",
           entity_id=n.id, detail={"ack": new.value, "note": body.note}, request=request)
    db.commit()
    return notification_item(n)


@router.post("/notifications/{notification_id}/evidence")
async def upload_evidence(notification_id: int, request: Request,
                          file: UploadFile = File(...), db: Session = Depends(get_db)):
    """조치 증빙 파일 업로드(§★★★★★)."""
    n = db.get(Notification, notification_id)
    if not n:
        raise HTTPException(404, "발송 내역 없음")
    content = await file.read()
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(413, f"파일 크기 초과(최대 {settings.MAX_UPLOAD_MB}MB)")
    # 온디스크 경로는 sanitize(traversal 차단), 표시용 원본명은 보존.
    path = EVIDENCE_DIR / f"notif{notification_id}_{safe_filename(file.filename)}"
    path.write_bytes(content)
    n.ack_evidence_path = str(path)
    n.ack_evidence_name = file.filename
    db.flush()
    record(db, action="NOTIFY_EVIDENCE", actor_id=get_actor_id(db), entity_type="notification",
           entity_id=n.id, detail={"file": file.filename}, request=request)
    db.commit()
    return notification_item(n)


@router.get("/notifications/{notification_id}/evidence")
def get_evidence(notification_id: int, db: Session = Depends(get_db)):
    """조치 증빙 파일 열람(inline). 첨부 없으면 404."""
    import os

    n = db.get(Notification, notification_id)
    if not n or not n.ack_evidence_path or not os.path.exists(n.ack_evidence_path):
        raise HTTPException(404, "증빙 파일이 없습니다")
    return FileResponse(n.ack_evidence_path, filename=n.ack_evidence_name or "evidence",
                        headers={"Content-Disposition":
                                 f"inline; filename=\"{n.ack_evidence_name or 'evidence'}\""})
