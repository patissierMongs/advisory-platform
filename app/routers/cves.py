"""CVE 데이터베이스 조회·수동 등록 (명세서 §5.2, §게이트)."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..core.extract import CVE_RE
from ..core.normalize import normalize_product
from ..db import get_db
from ..deps import get_actor_id
from ..models import Cve
from ..schemas import CveUpsertRequest
from ..serializers import cve_item
from .cve_feeds import _reevaluate_advisories

router = APIRouter(prefix="/api/v1", tags=["cves"])


@router.post("/cves", status_code=201)
def upsert_cve(body: CveUpsertRequest, request: Request, db: Session = Depends(get_db)):
    """CVE DB 수동 등록(§게이트) — 피드 없이 작업 화면에서 미등록 CVE 를 직접 등록.

    모든 필드는 선택(빈칸 허용) — 기본값은 게이트 화면의 본문 자동 추출 제안.
    등록 즉시 해당 CVE 를 참조하는 권고문 게이트를 재평가해 잠금을 해제한다.
    """
    m = CVE_RE.search((body.cve_id or "").replace(" ", "-"))
    if not m:
        raise HTTPException(400, "올바른 CVE 코드 형식이 아닙니다.")
    code = f"CVE-{m.group(1)}-{m.group(2)}"

    severity = enums.Severity.MEDIUM
    if body.severity:
        try:
            severity = enums.Severity(body.severity)
        except ValueError:
            raise HTTPException(400, "심각도는 CRITICAL·HIGH·MEDIUM·LOW 중 하나여야 합니다.")
    published = None
    if body.published_at:
        try:
            published = datetime.strptime(body.published_at[:10], "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(400, "날짜는 YYYY-MM-DD 형식이어야 합니다.")
    product_name = (body.product_name or "").strip() or None
    product_key = (body.product_key or "").strip() or (
        normalize_product(product_name) if product_name else None)
    versions = [v.strip() for v in (body.affected_versions or []) if v and v.strip()] or None

    cve = db.scalar(select(Cve).where(Cve.cve_id == code))
    created = cve is None
    if created:
        cve = Cve(cve_id=code, severity=severity, source=(body.source or "").strip() or "MANUAL")
        db.add(cve)
    # 전달된 필드만 갱신(기존 값 보존) — 재등록으로 피드 데이터를 비우지 않는다.
    if body.source and body.source.strip():
        cve.source = body.source.strip()
    if product_name:
        cve.product_name = product_name
    if product_key:
        cve.product_key = product_key
    if versions is not None:
        cve.affected_versions = versions
    if body.severity:
        cve.severity = severity
    if published:
        cve.published_at = published
    if body.description and body.description.strip():
        cve.description = body.description.strip()
    cve.is_manual = True   # 수동 등록 표식 — DB 화면에서 피드 유입분과 구분(§게이트)
    db.flush()

    unlocked = _reevaluate_advisories(db)
    record(db, action="CVE_DB_MANUAL_UPSERT", actor_id=get_actor_id(db), entity_type="cve",
           entity_id=cve.id, detail={"cve": code, "created": created, "unlocked": unlocked},
           request=request)
    db.commit()
    return {"cve": cve_item(cve), "created": created, "advisories_unlocked": unlocked}


@router.get("/cves")
def list_cves(
    q: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    page: int = 1,
    size: int = 100,
    db: Session = Depends(get_db),
):
    stmt = select(Cve).order_by(Cve.published_at.desc().nullslast(), Cve.id.desc())
    if q:
        like = f"%{q}%"
        # UI 검색창 안내('CVE, 제품, 출처 검색')와 일치 — 출처·제품키도 포함.
        stmt = stmt.where(or_(Cve.cve_id.ilike(like), Cve.product_name.ilike(like),
                              Cve.product_key.ilike(like), Cve.source.ilike(like)))
    if severity:
        stmt = stmt.where(Cve.severity == enums.Severity(severity))
    if source:
        stmt = stmt.where(Cve.source == source)
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.limit(size).offset((page - 1) * size)).all()
    return {"total": total, "items": [cve_item(c) for c in rows]}


@router.get("/cves/stats")
def cve_stats(db: Session = Depends(get_db)):
    count = db.scalar(select(func.count(Cve.id))) or 0
    last = db.scalar(select(func.max(Cve.updated_at))) or db.scalar(select(func.max(Cve.created_at)))
    return {"count": count, "last_updated": last.isoformat() if last else None}
