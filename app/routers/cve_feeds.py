"""CVE 피드 — 업로드·검증·적용 (명세서 §5.2, §4.4)."""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..config import DATA_DIR
from ..core import feeds
from ..core.extract import sha256_bytes
from ..core.files import safe_filename
from ..db import get_db
from ..deps import get_actor_id
from ..models import Advisory, AdvisoryCve, Cve, CveFeedImport

router = APIRouter(prefix="/api/v1", tags=["cve-feeds"])
FEED_DIR = DATA_DIR / "feeds"
FEED_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/cve-feeds")
async def upload_feed(
    request: Request,
    file: UploadFile = File(...),
    source: str | None = Form(None),
    db: Session = Depends(get_db),
):
    content = await file.read()
    try:
        records = feeds.parse_feed(file.filename or "", content)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"피드 파싱 실패: {e}")
    if not records:
        raise HTTPException(400, "유효한 CVE 레코드가 없습니다.")

    sha = sha256_bytes(content)
    path = FEED_DIR / f"{sha}_{safe_filename(file.filename)}"
    if not path.exists():
        path.write_bytes(content)

    added, updated = feeds.validate_counts(db, records)
    imp = CveFeedImport(
        source=source or (records[0].get("source") if records else None) or "UNKNOWN",
        import_mode=enums.ImportMode.FILE_UPLOAD,
        file_name=file.filename,
        file_sha256=sha,
        file_path=str(path),
        added_count=added,
        updated_count=updated,
        status=enums.FeedImportStatus.VALIDATED,
        staged_payload=_jsonable(records),
    )
    db.add(imp)
    db.flush()
    record(db, action="CVE_FEED_VALIDATE", actor_id=get_actor_id(db),
           entity_type="cve_feed_import", entity_id=imp.id,
           detail={"added": added, "updated": updated}, request=request)
    db.commit()
    return {
        "import_id": imp.id,
        "status": imp.status.value,
        "file_name": imp.file_name,
        "source": imp.source,
        "added_count": added,
        "updated_count": updated,
    }


@router.post("/cve-feeds/{import_id}/apply")
def apply_feed(import_id: int, request: Request, db: Session = Depends(get_db)):
    imp = db.get(CveFeedImport, import_id)
    if not imp:
        raise HTTPException(404, "피드 가져오기 내역 없음")
    if imp.status == enums.FeedImportStatus.APPLIED:
        raise HTTPException(409, "이미 적용된 피드입니다.")
    records = _from_jsonable(imp.staged_payload or [])
    added, updated = feeds.apply_records(db, records, imp.id)
    imp.added_count, imp.updated_count = added, updated
    imp.status = enums.FeedImportStatus.APPLIED
    imp.applied_at = datetime.now(timezone.utc)

    transitioned = _reevaluate_advisories(db)

    db.flush()
    record(db, action="CVE_FEED_APPLY", actor_id=get_actor_id(db),
           entity_type="cve_feed_import", entity_id=imp.id,
           detail={"added": added, "updated": updated, "advisories_unlocked": transitioned}, request=request)
    db.commit()
    return {"added_count": added, "updated_count": updated, "advisories_unlocked": transitioned}


@router.get("/cve-feeds")
def feed_history(db: Session = Depends(get_db)):
    rows = db.scalars(select(CveFeedImport).order_by(CveFeedImport.created_at.desc())).all()
    return {"items": [
        {
            "id": r.id,
            "source": r.source,
            "import_mode": r.import_mode.value,
            "file_name": r.file_name,
            "added_count": r.added_count,
            "updated_count": r.updated_count,
            "status": r.status.value,
            "applied_at": r.applied_at.isoformat() if r.applied_at else None,
            "time": (r.applied_at or r.created_at).isoformat() if (r.applied_at or r.created_at) else None,
        }
        for r in rows
    ]}


def _reevaluate_advisories(db: Session) -> int:
    """NOT_FOUND advisory_cve 재조회 → FOUND 전환, 잠금 해제된 advisory 수 반환."""
    pending = db.scalars(
        select(AdvisoryCve).where(AdvisoryCve.lookup_status == enums.LookupStatus.NOT_FOUND)
    ).all()
    touched_advisories: set[int] = set()
    for ac in pending:
        cve = db.scalar(select(Cve).where(Cve.cve_id == ac.cve_id_text))
        if cve:
            ac.cve_ref_id = cve.id
            ac.lookup_status = enums.LookupStatus.FOUND
            touched_advisories.add(ac.advisory_id)
    unlocked = 0
    for adv_id in touched_advisories:
        adv = db.get(Advisory, adv_id)
        if adv and adv.status == enums.AdvisoryStatus.NEEDS_CVE_UPDATE:
            if all(a.lookup_status == enums.LookupStatus.FOUND for a in adv.cves):
                adv.status = enums.AdvisoryStatus.EXTRACTED
                unlocked += 1
    return unlocked


def _jsonable(records: list[dict]) -> list[dict]:
    out = []
    for r in records:
        r = dict(r)
        r["severity"] = r["severity"].value if hasattr(r["severity"], "value") else r["severity"]
        if r.get("published_at") is not None and hasattr(r["published_at"], "isoformat"):
            r["published_at"] = r["published_at"].isoformat()
        out.append(r)
    return out


def _from_jsonable(records: list[dict]) -> list[dict]:
    from datetime import datetime as _dt

    out = []
    for r in records:
        r = dict(r)
        r["severity"] = enums.Severity(r["severity"]) if isinstance(r["severity"], str) else r["severity"]
        if isinstance(r.get("published_at"), str):
            try:
                r["published_at"] = _dt.strptime(r["published_at"][:10], "%Y-%m-%d").date()
            except ValueError:
                r["published_at"] = None
        out.append(r)
    return out
