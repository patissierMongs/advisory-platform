"""부서 관리 (명세서 §5.6)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Department
from ..schemas import DepartmentIn

router = APIRouter(prefix="/api/v1", tags=["departments"])


def _item(d: Department) -> dict:
    return {"id": d.id, "name": d.name, "code": d.code, "messenger_id": d.messenger_id,
            "email": d.email, "is_active": d.is_active}


@router.get("/departments")
def list_departments(db: Session = Depends(get_db)):
    rows = db.scalars(select(Department).order_by(Department.name)).all()
    return {"items": [_item(d) for d in rows]}


@router.post("/departments", status_code=201)
def create_department(body: DepartmentIn, db: Session = Depends(get_db)):
    if db.scalar(select(Department).where(Department.name == body.name)):
        raise HTTPException(409, "이미 존재하는 부서명")
    d = Department(**body.model_dump())
    db.add(d)
    db.commit()
    return _item(d)


@router.patch("/departments/{dept_id}")
def update_department(dept_id: int, body: DepartmentIn, db: Session = Depends(get_db)):
    d = db.get(Department, dept_id)
    if not d:
        raise HTTPException(404, "부서 없음")
    for k, v in body.model_dump().items():
        setattr(d, k, v)
    db.commit()
    return _item(d)
