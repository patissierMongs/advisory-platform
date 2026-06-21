from __future__ import annotations

import io
from pathlib import Path

from openpyxl import Workbook

from app.config import settings
from app.db import SessionLocal
from app.models import AssetImport
from app.routers.assets import ASSET_DIR


def _xlsx_bytes() -> io.BytesIO:
    wb = Workbook()
    ws = wb.active
    ws.append(["자산번호", "사용부서", "운영체제/SW", "세부버전", "담당자"])
    ws.append(["PC-1001", "정보보호팀", "Windows 11", "23H2", "홍길동"])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return buf


def _clear_assets():
    from sqlalchemy import delete

    with SessionLocal() as db:
        db.execute(delete(AssetImport))
        db.commit()


def test_asset_preview_rejects_files_over_configured_size(client):
    old_max = settings.MAX_UPLOAD_MB
    settings.MAX_UPLOAD_MB = 0
    try:
        r = client.post(
            "/api/v1/assets/import/preview",
            files={
                "file": (
                    "assets.xlsx",
                    _xlsx_bytes(),
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            },
        )
        assert r.status_code == 413
    finally:
        settings.MAX_UPLOAD_MB = old_max


def test_asset_preview_sanitizes_uploaded_filename(client):
    _clear_assets()
    r = client.post(
        "/api/v1/assets/import/preview",
        files={
            "file": (
                "x/../../assets.xlsx",
                _xlsx_bytes(),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
        },
    )
    assert r.status_code == 200
    import_id = r.json()["import_id"]

    with SessionLocal() as db:
        imp = db.get(AssetImport, import_id)
        assert imp is not None
        saved = Path(imp.file_path)

    assert saved.name == "import_assets.xlsx"
    assert saved.resolve().parent == ASSET_DIR.resolve()
    assert ".." not in saved.as_posix()
