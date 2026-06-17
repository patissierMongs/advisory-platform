"""매칭 — 실행/조회/오탐제외 (명세서 §5.4, §4.6). 서버측 게이트 강제."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..core import exclusions
from ..core.matching import all_cves_found, run_matching
from ..db import get_db
from ..deps import get_actor_id
from ..models import Advisory, Match
from ..schemas import MatchPatch
from ..serializers import match_item

router = APIRouter(prefix="/api/v1", tags=["matches"])


@router.post("/advisories/{advisory_id}/match")
def run_match(advisory_id: int, request: Request, db: Session = Depends(get_db)):
    adv = db.get(Advisory, advisory_id)
    if not adv:
        raise HTTPException(404, "권고문 없음")
    # 추출 진행 중에는 매칭 불가(반쯤 갱신된 CVE 목록 대상 매칭/고립 방지).
    if adv.status == enums.AdvisoryStatus.EXTRACTING or adv.extract_phase in ("queued", "regex", "llm"):
        raise HTTPException(409, detail={
            "code": "EXTRACTING", "message": "CVE 추출이 진행 중입니다. 완료 후 매칭하세요.",
        })
    # 게이트(서버 강제): 미등록 CVE 존재 시 매칭 불가.
    if not all_cves_found(adv):
        raise HTTPException(409, detail={
            "code": "NEEDS_CVE_UPDATE",
            "message": "DB 미등록 CVE가 있어 매칭할 수 없습니다. CVE 피드를 갱신하세요.",
        })
    result = run_matching(db, adv, actor_id=get_actor_id(db))
    record(db, action="ADVISORY_MATCH", actor_id=get_actor_id(db),
           entity_type="advisory", entity_id=adv.id, detail=result, request=request)
    db.commit()
    return result


@router.get("/advisories/{advisory_id}/matches")
def list_matches(advisory_id: int, db: Session = Depends(get_db)):
    rows = db.scalars(
        select(Match).where(Match.advisory_id == advisory_id).order_by(Match.id)
    ).all()
    items = [match_item(m) for m in rows]
    active = [i for i in items if i["status"] == "MATCHED"]
    return {
        "items": items,
        "summary": {
            "total": len(items),
            "active": len(active),
            "excluded": len(items) - len(active),
            "departments": len({i["department_id"] for i in active}),
            "candidates": sum(1 for i in active if i["candidate"]),
        },
    }


@router.patch("/matches/{match_id}")
def patch_match(match_id: int, body: MatchPatch, request: Request, db: Session = Depends(get_db)):
    m = db.get(Match, match_id)
    if not m:
        raise HTTPException(404, "매칭 없음")
    m.status = enums.MatchStatus(body.status)
    actor = get_actor_id(db)
    product_key = m.advisory_cve.cve.product_key if m.advisory_cve and m.advisory_cve.cve else None
    if m.status == enums.MatchStatus.EXCLUDED:
        m.excluded_by = actor
        m.excluded_reason = body.reason
        if product_key:  # 오탐 기억(§★★★): 다음 권고문에서 동일 조합 제외 제안
            exclusions.remember(db, m.asset_id, product_key, body.reason, actor)
    else:
        m.excluded_by = None
        m.excluded_reason = None
        if product_key:
            exclusions.forget(db, m.asset_id, product_key)
    db.flush()
    record(db, action="MATCH_EXCLUDE" if m.status == enums.MatchStatus.EXCLUDED else "MATCH_RESTORE",
           actor_id=get_actor_id(db), entity_type="match", entity_id=m.id,
           detail={"status": m.status.value, "reason": body.reason}, request=request)
    db.commit()
    return match_item(m)
