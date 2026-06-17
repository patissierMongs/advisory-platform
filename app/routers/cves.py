"""CVE 데이터베이스 조회 (명세서 §5.2)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import enums
from ..db import get_db
from ..models import Cve
from ..serializers import cve_item

router = APIRouter(prefix="/api/v1", tags=["cves"])


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
        stmt = stmt.where(or_(Cve.cve_id.ilike(like), Cve.product_name.ilike(like)))
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
