"""조치 회신·진척 + SLA + 리마인드 (§★★★★★ / §★★★★).

발송 후 단계를 채운다: 부서 회신 상태 집계, 권고문별 조치율, 기한(D-day) SLA,
미회신 부서 리마인드 대상 산출.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums
from ..models import Advisory, Notification

_OPEN = (
    enums.AdvisoryStatus.NOTIFYING,
    enums.AdvisoryStatus.MATCHED,
    enums.AdvisoryStatus.COMPLETED,
)


def _notifs(db: Session, advisory_id: int) -> list[Notification]:
    return db.scalars(
        select(Notification).where(Notification.advisory_id == advisory_id)
    ).all()


def advisory_remediation(db: Session, advisory: Advisory) -> dict:
    """권고문 1건의 조치 진척·조치율·SLA."""
    notifs = _notifs(db, advisory.id)
    total = len(notifs)
    by = {s: 0 for s in ("NONE", "IN_PROGRESS", "DONE", "UNABLE")}
    asset_total = asset_done = 0
    rows = []
    for n in notifs:
        ack = n.ack_status.value
        by[ack] = by.get(ack, 0) + 1
        cnt = len(n.asset_ids or [])
        asset_total += cnt
        if n.ack_status == enums.AckStatus.DONE:
            asset_done += cnt
        rows.append({
            "notification_id": n.id,
            "department_id": n.department_id,
            "department": n.department.name if n.department else None,
            "ack_status": ack,
            "ack_status_ko": enums.ACK_KO.get(n.ack_status, ack),
            "ack_note": n.ack_note,
            "ack_by": n.ack_by,
            "ack_updated_at": _iso(n.ack_updated_at),
            "evidence": n.ack_evidence_name,
            "asset_count": cnt,
            "sent_at": _iso(n.sent_at),
            "reminded_at": _iso(n.reminded_at),
            "reminder_count": n.reminder_count,
            "channels": n.channels,
        })

    # 조치 완료/불가는 '회신 종료'로 간주(진행 필요 없음).
    closed = by["DONE"] + by["UNABLE"]
    all_done = total > 0 and closed == total
    done_rate = round(by["DONE"] / total * 100) if total else 0
    responded_rate = round((total - by["NONE"]) / total * 100) if total else 0

    return {
        "advisory_id": advisory.id,
        "doc_no": advisory.doc_no,
        "title": advisory.title,
        "due_at": _iso(advisory.due_at),
        "d_day": (advisory.due_at - date.today()).days if advisory.due_at else None,
        "sla_status": enums.sla_status(advisory.due_at, all_done).value,
        "dept_total": total,
        "none": by["NONE"],
        "in_progress": by["IN_PROGRESS"],
        "done": by["DONE"],
        "unable": by["UNABLE"],
        "done_rate": done_rate,
        "responded_rate": responded_rate,
        "asset_total": asset_total,
        "asset_done": asset_done,
        "departments": rows,
    }


def due_reminders(db: Session, within_days: int = 3) -> list[dict]:
    """기한 임박(D-within ~ 초과) + 미회신 부서 리마인드 대상."""
    today = date.today()
    out = []
    advs = db.scalars(select(Advisory).where(Advisory.status.in_(_OPEN))).all()
    for adv in advs:
        if adv.due_at is None:
            continue
        d_day = (adv.due_at - today).days
        if d_day > within_days:
            continue  # 아직 여유
        for n in _notifs(db, adv.id):
            if n.ack_status in (enums.AckStatus.DONE, enums.AckStatus.UNABLE):
                continue  # 회신 종료
            out.append({
                "advisory_id": adv.id,
                "doc_no": adv.doc_no,
                "notification_id": n.id,
                "department_id": n.department_id,
                "department": n.department.name if n.department else None,
                "ack_status": n.ack_status.value,
                "d_day": d_day,
                "overdue": d_day < 0,
                "reminder_count": n.reminder_count,
                "last_reminded": _iso(n.reminded_at),
            })
    # 임박/초과 순.
    out.sort(key=lambda r: (r["d_day"]))
    return out


def sla_overview(db: Session) -> dict:
    """대시보드용 SLA 요약(진행 중 권고문 기준)."""
    advs = db.scalars(select(Advisory).where(Advisory.status.in_(_OPEN))).all()
    counts = {"NORMAL": 0, "IMMINENT": 0, "OVERDUE": 0, "DONE": 0}
    for adv in advs:
        notifs = _notifs(db, adv.id)
        closed = sum(1 for n in notifs if n.ack_status in (enums.AckStatus.DONE, enums.AckStatus.UNABLE))
        all_done = len(notifs) > 0 and closed == len(notifs)
        counts[enums.sla_status(adv.due_at, all_done).value] += 1
    return counts


def _iso(v: datetime | date | None) -> str | None:
    return v.isoformat() if v is not None else None
