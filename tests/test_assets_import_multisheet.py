"""§개편 — 자산 엑셀 다중 시트: 미리보기 시트 목록·시트 선택·전체 시트 일괄 적재."""
from __future__ import annotations

import io

from openpyxl import Workbook
from sqlalchemy import delete

from app.db import SessionLocal
from app.models import Asset, Department


def _two_sheet_xlsx() -> bytes:
    wb = Workbook()
    ws1 = wb.active
    ws1.title = "정보보호팀"
    ws1.append(["자산번호", "부서", "제품", "버전", "담당자"])
    ws1.append(["MS-001", "정보보호팀", "nginx", "1.20", "김보안"])
    ws2 = wb.create_sheet("전산실")
    ws2.append(["자산번호", "부서", "제품", "버전", "담당자"])
    ws2.append(["MS-002", "전산실", "Apache Tomcat", "9.0.10", "이운영"])
    ws2.append(["MS-003", "전산실", "Apache Storm", "2.3.0", "이운영"])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


MAPPING = {"asset_no": "A", "department": "B", "product_key": "C",
           "version_norm": "D", "owner_name": "E"}


def _cleanup():
    with SessionLocal() as db:
        db.execute(delete(Asset).where(Asset.asset_no.in_(["MS-001", "MS-002", "MS-003"])))
        db.execute(delete(Department).where(Department.name.in_(["정보보호팀", "전산실"])))
        db.commit()


def test_preview_lists_all_sheets_and_can_select(client):
    data = _two_sheet_xlsx()
    r = client.post("/api/v1/assets/import/preview",
                    files={"file": ("multi.xlsx", io.BytesIO(data),
                                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert r.status_code == 200
    pv = r.json()
    assert pv["sheets"] == ["정보보호팀", "전산실"]
    assert pv["sheet"] == "정보보호팀"

    # 두 번째 시트 선택 미리보기.
    r = client.post("/api/v1/assets/import/preview",
                    files={"file": ("multi.xlsx", io.BytesIO(data),
                                    "application/octet-stream")},
                    data={"sheet": "전산실"})
    pv2 = r.json()
    assert pv2["sheet"] == "전산실"
    assert any("MS-002" in (c["samples"] or []) for c in pv2["columns"])


def test_commit_all_sheets_imports_every_sheet(client):
    try:
        data = _two_sheet_xlsx()
        r = client.post("/api/v1/assets/import/preview",
                        files={"file": ("multi.xlsx", io.BytesIO(data),
                                        "application/octet-stream")})
        import_id = r.json()["import_id"]
        r = client.post(f"/api/v1/assets/import/{import_id}/commit",
                        json={"mapping": MAPPING, "all_sheets": True})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["committed"] == 3
        assert body["sheets_imported"] == ["정보보호팀", "전산실"]

        with SessionLocal() as db:
            storm = db.query(Asset).filter_by(asset_no="MS-003").one()
            # Apache Storm 이 apache_httpd 로 오정규화되지 않는다(§개편).
            assert storm.product_key == "apache_storm"
            tomcat = db.query(Asset).filter_by(asset_no="MS-002").one()
            assert tomcat.product_key == "apache_tomcat"
    finally:
        _cleanup()
