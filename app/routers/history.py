"""발송이력 · 조치관리 — 관리자 콘솔(마스터-디테일).

드롭다운 한 줄로 보던 발송이력을, 권고문별·부서별로 한눈에 보는 리스트로 재설계한다.
  · 조치현황 시각화: 권고문별 부서 ack 분포(완료/진행중/불가/미회신) 집계.
  · 게시판 ↔ 발송이력 동기화: 부서 회신(댓글 ack)이 발송이력 ack 로 반영된 결과를 그대로 노출.
  · 발송 문구 프리셋(추가/삭제): 미회신 부서 재발송 시 본문 템플릿.
정렬·필터·검색은 한 번에 받은 롤업 위에서 화면이 계산한다(내부 소규모 데이터, 즉응성 우선).
"""
from __future__ import annotations

from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums, serializers
from ..audit import record
from ..db import get_db
from ..models import Advisory, Asset, Match, MessageTemplate, Notification
from ..schemas import MessageTemplateIn

router = APIRouter(prefix="/api/v1", tags=["history"])

_SEV_RANK = {
    enums.Severity.CRITICAL: 4, enums.Severity.HIGH: 3,
    enums.Severity.MEDIUM: 2, enums.Severity.LOW: 1,
}


def _max_severity(a: Advisory):
    sevs = [ac.cve.severity for ac in a.cves if ac.cve and not ac.is_deleted]
    if not sevs:
        return None
    return max(sevs, key=lambda s: _SEV_RANK.get(s, 0))


def _owner_map(db: Session, asset_ids: set[int]) -> dict[int, str | None]:
    """asset_id → 담당자명 일괄 조회(발송 대상 자산의 담당자 표시용)."""
    if not asset_ids:
        return {}
    rows = db.execute(
        select(Asset.id, Asset.owner_name).where(Asset.id.in_(asset_ids))
    ).all()
    return {aid: name for aid, name in rows}


@router.get("/history/advisories")
def history_advisories(db: Session = Depends(get_db)):
    """발송된 권고문별 조치현황 롤업 — 부서 ack 분포 + 부서별 회신 상태.

    발송 내역(Notification)이 하나라도 있는 권고문만 대상(= 실제 발송된 것).
    화면(권고문별/부서별 뷰)은 이 응답 하나로 검색·필터·정렬을 모두 계산한다.
    """
    notifs = db.scalars(select(Notification)).all()

    # 담당자명 일괄 매핑(발송 자산 기준).
    all_asset_ids: set[int] = set()
    for n in notifs:
        all_asset_ids.update(n.asset_ids or [])
    owners = _owner_map(db, all_asset_ids)

    by_adv: dict[int, list[Notification]] = {}
    for n in notifs:
        by_adv.setdefault(n.advisory_id, []).append(n)

    # ── 자산(개별 대상) 단위 ack 집계(§개편) — 부서 묶음이 아닌 개별 자산 기준 조치율.
    #    (advisory_id, department_id) → {total, done, in_progress, unable, none}
    asset_ack: dict[tuple[int, int], dict[str, int]] = {}
    if by_adv:
        rows = db.execute(
            select(Match.advisory_id, Asset.department_id, Match.ack_status)
            .join(Asset, Match.asset_id == Asset.id)
            .where(Match.advisory_id.in_(by_adv.keys()),
                   Match.status == enums.MatchStatus.MATCHED)
        ).all()
        for adv_id, dept_id, ack in rows:
            c = asset_ack.setdefault((adv_id, dept_id), {
                "total": 0, "done": 0, "in_progress": 0, "unable": 0, "none": 0})
            c["total"] += 1
            key = {"DONE": "done", "IN_PROGRESS": "in_progress",
                   "UNABLE": "unable"}.get(ack.value, "none")
            c[key] += 1

    today = date.today()
    items = []
    for advisory_id, ns in by_adv.items():
        adv = db.get(Advisory, advisory_id)
        if adv is None:
            continue
        counts = {"NONE": 0, "IN_PROGRESS": 0, "DONE": 0, "UNABLE": 0}
        adv_assets = {"total": 0, "done": 0, "in_progress": 0, "unable": 0, "none": 0}
        depts = []
        for n in sorted(ns, key=lambda x: (x.department.name if x.department else "")):
            counts[n.ack_status.value] = counts.get(n.ack_status.value, 0) + 1
            n_owners = sorted({owners.get(aid) for aid in (n.asset_ids or [])} - {None, "자동배포"})
            aa = asset_ack.get((advisory_id, n.department_id))
            if aa:
                for k in adv_assets:
                    adv_assets[k] += aa[k]
            depts.append({
                # 개별 대상(자산) 단위 조치 집계(§개편) — 부서 단일 상태와 별개로 표기.
                "asset_ack": dict(aa) | {
                    "done_rate": round(aa["done"] / aa["total"] * 100) if aa["total"] else 0,
                } if aa else None,
                "notification_id": n.id,
                "department_id": n.department_id,
                "department": n.department.name if n.department else None,
                "owners": n_owners,
                "owner": ", ".join(n_owners) if n_owners else None,
                "ack_status": n.ack_status.value,
                "ack_status_ko": enums.ACK_KO.get(n.ack_status, n.ack_status.value),
                "ack_note": n.ack_note,
                "ack_by": n.ack_by,
                "ack_updated_at": serializers._d(n.ack_updated_at),
                "evidence": n.ack_evidence_name,
                "has_evidence": n.ack_evidence_path is not None,
                "asset_count": len(n.asset_ids or []),
                "status": n.status.value,
                "reminder_count": n.reminder_count,
                "sent_at": serializers._d(n.sent_at),
            })
        total = len(depts)
        done = counts["DONE"]
        closed = counts["DONE"] + counts["UNABLE"]
        sev = _max_severity(adv)
        d_day = (adv.due_at - today).days if adv.due_at else None
        items.append({
            "id": adv.id,
            "doc_no": adv.doc_no,
            "title": adv.title,
            "source_org": adv.source_org,
            "receive_channel": adv.receive_channel.value if adv.receive_channel else None,
            "due_at": serializers._d(adv.due_at),
            "d_day": d_day,
            "sla_status": enums.sla_status(adv.due_at, total > 0 and closed == total, today).value,
            "max_severity": sev.value if sev else None,
            "max_severity_ko": enums.SEVERITY_KO.get(sev) if sev else None,
            "board_published": adv.board_published_at is not None,
            "dept_total": total,
            "none": counts["NONE"],
            "in_progress": counts["IN_PROGRESS"],
            "done": done,
            "unable": counts["UNABLE"],
            "done_rate": round(done / total * 100) if total else 0,
            "responded_rate": round((total - counts["NONE"]) / total * 100) if total else 0,
            # 개별 대상(자산) 단위 합계(§개편) — 권고문 전체 자산 조치율.
            "asset_total": adv_assets["total"],
            "asset_done": adv_assets["done"],
            "asset_in_progress": adv_assets["in_progress"],
            "asset_unable": adv_assets["unable"],
            "asset_none": adv_assets["none"],
            "asset_done_rate": (round(adv_assets["done"] / adv_assets["total"] * 100)
                                if adv_assets["total"] else 0),
            "departments": depts,
        })

    # 기본 정렬: 기한 임박순(기한 없는 건 뒤로). 화면에서 재정렬 가능.
    items.sort(key=lambda x: (x["d_day"] is None, x["d_day"] if x["d_day"] is not None else 0))
    return {"items": items, "total": len(items)}


# ── 발송 문구 프리셋(추가/삭제) ──
@router.get("/message-templates")
def list_templates(db: Session = Depends(get_db)):
    rows = db.scalars(select(MessageTemplate).order_by(MessageTemplate.id)).all()
    return {"items": [serializers.message_template_item(t) for t in rows]}


@router.post("/message-templates", status_code=201)
def add_template(body: MessageTemplateIn, request: Request, db: Session = Depends(get_db)):
    t = MessageTemplate(title=body.title.strip(), body=body.body.strip())
    db.add(t)
    db.flush()
    record(db, action="TEMPLATE_ADD", actor_id=None, entity_type="message_template",
           entity_id=t.id, detail={"title": t.title}, request=request)
    db.commit()
    db.refresh(t)
    return serializers.message_template_item(t)


@router.delete("/message-templates/{template_id}", status_code=204)
def delete_template(template_id: int, request: Request, db: Session = Depends(get_db)):
    t = db.get(MessageTemplate, template_id)
    if not t:
        raise HTTPException(404, "프리셋 없음")
    db.delete(t)
    record(db, action="TEMPLATE_DELETE", actor_id=None, entity_type="message_template",
           entity_id=template_id, detail=None, request=request)
    db.commit()
    return None
