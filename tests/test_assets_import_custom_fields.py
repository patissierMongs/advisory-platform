"""자산 import — 사용자 정의(선택) 필드 자유 추가: 시스템 필드가 아닌 매핑 키는
Asset.extra 에 '이름 그대로' 저장되고, 매핑 안 된 컬럼만 레터 키로 폴백됨을 검증."""
from __future__ import annotations

import io

from openpyxl import Workbook


def _xlsx_bytes():
    wb = Workbook(); ws = wb.active
    ws.append(["부서", "제품", "구매일자", "비고"])
    ws.append(["정보화담당관실", "Windows 11 23H2", "2025-01-15", "리스자산"])
    ws.append(["도로국", "Microsoft Office 2021", "2024-11-02", ""])
    buf = io.BytesIO(); wb.save(buf); return buf.getvalue()


def test_custom_named_field_stored_in_extra(client):
    files = {"file": ("assets.xlsx", _xlsx_bytes(),
                      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
    pv = client.post("/api/v1/assets/import/preview", files=files)
    assert pv.status_code == 200, pv.text
    import_id = pv.json()["import_id"]

    # 시스템 부서/제품 + 사용자 정의 '구매일자'(이름 키). '비고'는 매핑 안 함 → 레터 폴백.
    body = {"mapping": {"department": "A", "product_key": "B", "구매일자": "C"},
            "mode": "append", "on_warning": "skip", "header_rows": 1}
    r = client.post(f"/api/v1/assets/import/{import_id}/commit", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["committed"] == 2, r.json()

    from app.db import SessionLocal
    from app.models import Asset, Department
    with SessionLocal() as db:
        dept = db.query(Department).filter(Department.name == "정보화담당관실").first()
        a = db.query(Asset).filter(Asset.department_id == dept.id).first()
        assert a is not None
        assert a.extra.get("구매일자") == "2025-01-15", a.extra   # 이름 키 저장 ✅
        assert a.extra.get("D") == "리스자산", a.extra            # 미매핑 → 레터 폴백 ✅
        assert "C" not in a.extra, a.extra                        # 매핑된 커스텀은 레터 중복 없음 ✅


def test_required_field_validation_unaffected(client):
    """사용자 정의 필드만 있고 필수(부서·제품) 누락 시 400."""
    files = {"file": ("assets.xlsx", _xlsx_bytes(),
                      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")}
    import_id = client.post("/api/v1/assets/import/preview", files=files).json()["import_id"]
    r = client.post(f"/api/v1/assets/import/{import_id}/commit",
                    json={"mapping": {"구매일자": "C"}, "mode": "append", "on_warning": "skip"})
    assert r.status_code == 400, r.text
