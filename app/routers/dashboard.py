"""대시보드 집계 (명세서 §5.6)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import distinct, func, select
from sqlalchemy.orm import Session

from collections import defaultdict

from .. import enums
from ..core import remediation
from ..db import get_db
from ..models import Advisory, AdvisoryCve, Asset, Department, Match, Notification
from ..serializers import advisory_brief

router = APIRouter(prefix="/api/v1", tags=["dashboard"])

_IN_PROGRESS = [
    enums.AdvisoryStatus.UPLOADED, enums.AdvisoryStatus.EXTRACTING, enums.AdvisoryStatus.EXTRACTED,
    enums.AdvisoryStatus.NEEDS_CVE_UPDATE, enums.AdvisoryStatus.MATCHED, enums.AdvisoryStatus.NOTIFYING,
]


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db)):
    in_progress = db.scalar(
        select(func.count(Advisory.id)).where(Advisory.status.in_(_IN_PROGRESS))
    ) or 0
    not_found = db.scalar(
        select(func.count(distinct(AdvisoryCve.cve_id_text)))
        .where(AdvisoryCve.lookup_status == enums.LookupStatus.NOT_FOUND)
    ) or 0
    asset_total = db.scalar(select(func.count(Asset.id))) or 0
    matched_assets = db.scalar(
        select(func.count(distinct(Match.asset_id))).where(Match.status == enums.MatchStatus.MATCHED)
    ) or 0

    # 부서별 조치 진척: 발송 건 대비 회신(DONE) 비율.
    agg: dict[int, list[int]] = defaultdict(lambda: [0, 0])  # [done, total]
    for n in db.scalars(select(Notification)):
        agg[n.department_id][1] += 1
        if n.ack_status == enums.AckStatus.DONE:
            agg[n.department_id][0] += 1
    dept_names = {d.id: d.name for d in db.scalars(select(Department))}
    dept_progress = [
        {"department_id": dept_id, "dept": dept_names.get(dept_id, str(dept_id)),
         "pct": round(done / total * 100) if total else 0}
        for dept_id, (done, total) in agg.items()
    ]

    recent = db.scalars(select(Advisory).order_by(Advisory.created_at.desc()).limit(5)).all()
    sla = remediation.sla_overview(db)
    due = remediation.due_reminders(db)

    return {
        "stats": [
            {"key": "in_progress", "label": "진행 중 권고문", "value": in_progress, "unit": "건"},
            {"key": "not_found_cve", "label": "DB 미등록 CVE", "value": not_found, "unit": "건"},
            {"key": "target_assets", "label": "대상 자산", "value": matched_assets or asset_total, "unit": "대"},
            {"key": "overdue", "label": "기한 초과", "value": sla.get("OVERDUE", 0), "unit": "건"},
            {"key": "due_reminders", "label": "리마인드 대상", "value": len(due), "unit": "건"},
        ],
        "sla": sla,
        "due_reminders": len(due),
        "recent_advisories": [advisory_brief(a) for a in recent],
        "dept_progress": dept_progress,
    }
