"""포트스캔 회차 import/조회 — 독립 스캐너(portscan-tool)의 nmap XML 회차를 콘솔로.

설계: 회차 폴더(여러 nmap XML + 선택적 4_unknown/*.txt 배너)를 zip 으로 업로드.
서버가 무손실 병합 → DB 영속(ScanRun/ScanPort). 직전 회차 대비 diff(신규/폐쇄)로
'열린 포트 감소(결과)'를 추적.
"""
from __future__ import annotations

import io
import zipfile

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import serializers
from ..audit import record
from ..core import scan_import
from ..db import get_db
from ..models import ScanPort, ScanRun

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

# 업로드 가드(폐쇄망 내부용이지만 zip-bomb·메모리 폭주 방지).
_MAX_ZIP_BYTES = 100 * 1024 * 1024        # 압축 파일 자체 100MB
_MAX_UNCOMPRESSED = 500 * 1024 * 1024     # 압축 해제 총량 500MB
_MAX_MEMBERS = 5000                        # 멤버 파일 수


@router.post("/import", status_code=201)
async def import_scan(request: Request, file: UploadFile = File(...),
                      label: str = Form(""), network: str = Form(""),
                      db: Session = Depends(get_db)):
    """회차 폴더 zip 업로드 → nmap XML 병합 → ScanRun + ScanPort 저장."""
    data = await file.read()
    if len(data) > _MAX_ZIP_BYTES:
        raise HTTPException(413, f"zip 이 너무 큽니다(최대 {_MAX_ZIP_BYTES // (1024*1024)}MB).")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise HTTPException(400, "zip 파일이 아닙니다(회차 폴더를 zip 으로 업로드).")

    # zip-bomb 방어: 멤버 수 + 압축 해제 총량 상한.
    infos = zf.infolist()
    if len(infos) > _MAX_MEMBERS:
        raise HTTPException(400, "zip 안 파일이 너무 많습니다(비정상 압축).")
    if sum(i.file_size for i in infos) > _MAX_UNCOMPRESSED:
        raise HTTPException(400, "압축 해제 용량이 과도합니다(zip-bomb 방지).")

    xml_blobs: list[bytes] = []
    banners: dict[tuple[str, str, int], str] = {}
    for name in zf.namelist():
        low = name.lower()
        if low.endswith(".xml"):
            xml_blobs.append(zf.read(name))
        elif low.endswith(".txt") and "unknown" in low:
            try:
                banners.update(scan_import.parse_banner_txt(zf.read(name).decode("utf-8", "replace")))
            except Exception:  # noqa: BLE001 — 깨진 배너 한 건이 import 막지 않게
                pass
    if not xml_blobs:
        raise HTTPException(400, "zip 안에 nmap XML(.xml) 이 없습니다.")

    records, counts = scan_import.parse_scan(xml_blobs, banners)
    if not records:
        raise HTTPException(400, "열린 포트가 없습니다(스캔 결과가 비어 있음).")

    run = ScanRun(
        label=(label.strip() or file.filename or "scan"),
        network=(network.strip() or None),
        source_name=file.filename,
        host_count=counts["host_count"],
        open_port_count=counts["open_port_count"],
        identified_count=counts["identified_count"],
    )
    db.add(run)
    db.flush()
    for r in records:
        db.add(ScanPort(scan_run_id=run.id, host=r["host"], hostname=r["hostname"],
                        proto=r["proto"], port=r["port"], state=r["state"], reason=r["reason"],
                        service=r["service"], product=r["product"], version=r["version"],
                        extra=r["extra"], identified=r["identified"], evidence=r["evidence"],
                        banner=r["banner"], note=r["note"]))
    record(db, action="SCAN_IMPORT", actor_id=None, entity_type="scan_run", entity_id=run.id,
           detail={"label": run.label, "network": run.network, **counts}, request=request)
    db.commit()
    db.refresh(run)
    return {"run": serializers.scan_run_item(run)}


@router.get("")
def list_runs(db: Session = Depends(get_db)):
    rows = db.scalars(select(ScanRun).order_by(ScanRun.id.desc())).all()
    return {"items": [serializers.scan_run_item(r) for r in rows]}


def _prev_run(db: Session, run: ScanRun) -> ScanRun | None:
    """같은 망구분의 직전 회차(이전 id). 망구분 없으면 전체 기준."""
    q = select(ScanRun).where(ScanRun.id < run.id)
    if run.network:
        q = q.where(ScanRun.network == run.network)
    return db.scalars(q.order_by(ScanRun.id.desc())).first()


@router.get("/{run_id}")
def get_run(run_id: int, db: Session = Depends(get_db)):
    run = db.get(ScanRun, run_id)
    if not run:
        raise HTTPException(404, "회차 없음")
    ports = db.scalars(
        select(ScanPort).where(ScanPort.scan_run_id == run_id)
        .order_by(ScanPort.host, ScanPort.proto, ScanPort.port)
    ).all()
    prev = _prev_run(db, run)
    return {
        "run": serializers.scan_run_item(run),
        "ports": [serializers.scan_port_item(p) for p in ports],
        "prev_run_id": prev.id if prev else None,
    }


@router.get("/{run_id}/diff")
def diff_run(run_id: int, vs: int | None = None, db: Session = Depends(get_db)):
    """직전(또는 지정 vs) 회차 대비 신규/폐쇄 포트. 열린 포트 감소 추적용."""
    run = db.get(ScanRun, run_id)
    if not run:
        raise HTTPException(404, "회차 없음")
    prev = db.get(ScanRun, vs) if vs else _prev_run(db, run)
    if not prev:
        return {"prev_run_id": None, "new": [], "closed": [],
                "new_count": 0, "closed_count": 0}

    def keyset(rid):
        rows = db.scalars(select(ScanPort).where(ScanPort.scan_run_id == rid)).all()
        return {(p.host, p.proto, p.port): p for p in rows}

    cur, old = keyset(run.id), keyset(prev.id)
    new = [serializers.scan_port_item(cur[k]) for k in cur if k not in old]
    closed = [serializers.scan_port_item(old[k]) for k in old if k not in cur]
    new.sort(key=lambda r: (r["host"], r["proto"], r["port"]))
    closed.sort(key=lambda r: (r["host"], r["proto"], r["port"]))
    return {"prev_run_id": prev.id, "prev_label": prev.label,
            "new": new, "closed": closed, "new_count": len(new), "closed_count": len(closed)}


@router.delete("/{run_id}", status_code=204)
def delete_run(run_id: int, request: Request, db: Session = Depends(get_db)):
    run = db.get(ScanRun, run_id)
    if not run:
        raise HTTPException(404, "회차 없음")
    db.delete(run)
    record(db, action="SCAN_DELETE", actor_id=None, entity_type="scan_run",
           entity_id=run_id, detail={"label": run.label}, request=request)
    db.commit()
    return None
