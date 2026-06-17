"""CVE 피드 — 업로드·검증·적용 (명세서 §5.2, §4.4)."""
from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..config import DATA_DIR
from ..core import feeds
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
    # 대용량(1.6GB+) 대비: 메모리에 통째로 올리지 않고 디스크로 청크 스트리밍 저장(+sha 동시 계산).
    h = hashlib.sha256()
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(FEED_DIR))
    try:
        with os.fdopen(tmp_fd, "wb") as out:
            while chunk := await file.read(1 << 20):
                h.update(chunk)
                out.write(chunk)
    except BaseException:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise
    sha = h.hexdigest()
    path = FEED_DIR / f"{sha}_{safe_filename(file.filename)}"
    newly_created = not path.exists()
    if newly_created:
        os.replace(tmp_path, path)
    else:
        os.remove(tmp_path)  # 동일 sha 기존 파일 재사용

    # 검증: 원본 파일에서 스트리밍하며 신규/갱신 카운트(상수 메모리).
    try:
        added, updated, first_source = feeds.count_new_updated(
            db, feeds.iter_records_from_path(str(path), file.filename))
    except Exception as e:  # noqa: BLE001
        if newly_created:
            path.unlink(missing_ok=True)
        raise HTTPException(400, f"피드 파싱 실패: {e}")
    if added + updated == 0:
        if newly_created:
            path.unlink(missing_ok=True)
        raise HTTPException(400, "유효한 CVE 레코드가 없습니다.")

    imp = CveFeedImport(
        source=source or first_source or "UNKNOWN",
        import_mode=enums.ImportMode.FILE_UPLOAD,
        file_name=file.filename,
        file_sha256=sha,
        file_path=str(path),
        added_count=added,
        updated_count=updated,
        status=enums.FeedImportStatus.VALIDATED,
        # staged_payload 미사용: 적용 시 원본 파일(file_path)에서 재파싱 — DB 비대화·이중 적재 방지.
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
    if not imp.file_path or not os.path.exists(imp.file_path):
        raise HTTPException(410, "원본 피드 파일이 없어 적용할 수 없습니다. 다시 업로드하세요.")
    imp_id = imp.id
    # 원본 파일에서 스트리밍 → 배치 단위 upsert·커밋(상수 메모리, 중단 후 재적용 안전).
    added, updated = feeds.apply_stream(
        db, feeds.iter_records_from_path(imp.file_path, imp.file_name), imp_id)
    imp = db.get(CveFeedImport, imp_id)  # 배치 커밋으로 만료 → 명시적 재취득
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
