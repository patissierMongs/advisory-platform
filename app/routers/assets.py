"""자산 — 목록 / 엑셀 가져오기(미리보기·커밋) / 매핑 프리셋 (명세서 §5.3, §4.5)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..config import DATA_DIR
from ..core import assets_import
from ..db import get_db
from ..deps import get_actor_id
from ..models import Asset, AssetImport, AssetImportMapping, Department
from ..schemas import AssetCommitRequest, MappingPresetIn
from ..serializers import asset_item

router = APIRouter(prefix="/api/v1", tags=["assets"])
ASSET_DIR = DATA_DIR / "assets"
ASSET_DIR.mkdir(parents=True, exist_ok=True)


@router.get("/assets")
def list_assets(
    department: str | None = None,
    product_key: str | None = None,
    q: str | None = None,
    page: int = 1,
    size: int = 200,
    db: Session = Depends(get_db),
):
    depts = {d.id: d.name for d in db.scalars(select(Department))}
    stmt = select(Asset).order_by(Asset.asset_no)
    if product_key:
        stmt = stmt.where(Asset.product_key == product_key)
    if department:
        dept = db.scalar(select(Department).where(Department.name == department))
        stmt = stmt.where(Asset.department_id == (dept.id if dept else -1))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Asset.asset_no.ilike(like), Asset.product_raw.ilike(like),
                              Asset.owner_name.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    rows = db.scalars(stmt.limit(size).offset((page - 1) * size)).all()
    return {"total": total, "items": [asset_item(a, dept_name=depts.get(a.department_id)) for a in rows]}


@router.post("/assets/import/preview")
async def import_preview(
    file: UploadFile = File(...),
    sheet: str | None = Form(None),
    header_row: int | None = Form(None),
    header_rows: int = Form(1),
    db: Session = Depends(get_db),
):
    content = await file.read()
    path = ASSET_DIR / f"import_{file.filename}"
    path.write_bytes(content)
    imp = AssetImport(file_name=file.filename, sheet_name=sheet,
                      status=enums.AssetImportStatus.PREVIEW, file_path=str(path))
    db.add(imp)
    db.flush()
    try:
        pv = assets_import.preview(str(path), sheet, header_row=header_row, header_rows=header_rows)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(400, f"엑셀 미리보기 실패: {e}")
    imp.sheet_name = pv["sheet"]
    imp.row_count = pv["total_rows"]
    db.commit()
    return {"import_id": imp.id, **pv}


@router.post("/assets/import/{import_id}/commit")
def import_commit(import_id: int, body: AssetCommitRequest, request: Request, db: Session = Depends(get_db)):
    imp = db.get(AssetImport, import_id)
    if not imp or not imp.file_path:
        raise HTTPException(404, "가져오기 배치 없음")
    missing = [f for f in assets_import.REQUIRED_FIELDS if f not in body.mapping]
    if missing:
        raise HTTPException(400, f"필수 매핑 누락: {', '.join(missing)}")
    result = assets_import.commit(
        db, imp.file_path, body.sheet or imp.sheet_name, body.mapping,
        import_batch_id=imp.id, mode=body.mode, on_warning=body.on_warning,
        header_row=body.header_row, header_rows=body.header_rows,
        create_departments=body.create_departments,
    )
    imp.mapping = body.mapping
    imp.row_count = result["total_rows"]
    imp.status = enums.AssetImportStatus.COMMITTED
    db.flush()
    record(db, action="ASSET_IMPORT_COMMIT", actor_id=get_actor_id(db),
           entity_type="asset_import", entity_id=imp.id,
           detail={"committed": result["committed"], "warnings": len(result["warnings"])}, request=request)
    db.commit()
    return result


@router.get("/import-mappings")
def list_presets(db: Session = Depends(get_db)):
    rows = db.scalars(select(AssetImportMapping).order_by(AssetImportMapping.name)).all()
    return {"items": [{"id": r.id, "name": r.name, "mapping": r.mapping} for r in rows]}


@router.post("/import-mappings", status_code=201)
def save_preset(body: MappingPresetIn, db: Session = Depends(get_db)):
    existing = db.scalar(select(AssetImportMapping).where(AssetImportMapping.name == body.name))
    if existing:
        existing.mapping = body.mapping
        preset = existing
    else:
        preset = AssetImportMapping(name=body.name, mapping=body.mapping)
        db.add(preset)
    db.commit()
    return {"id": preset.id, "name": preset.name, "mapping": preset.mapping}
