"""설정 파일 관리 API — '파일로 관리하고 웹에서 편집' 원칙의 공용 엔드포인트.

모든 설정은 data/config/<name>.json 파일이 원본이다. 이 API 는 그 파일을
읽고(웹 표시) 검증 후 다시 쓰는(웹 편집) 얇은 계층일 뿐이며, 파일을 직접
수정해도 mtime 캐시로 즉시 반영된다.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..audit import record
from ..core import appconfig
from ..db import get_db
from ..deps import get_actor_id

router = APIRouter(prefix="/api/v1", tags=["config"])


class ConfigPut(BaseModel):
    value: dict


@router.get("/config")
def list_configs():
    return {"items": appconfig.list_configs()}


@router.get("/config/{name}")
def get_config(name: str):
    try:
        value = appconfig.get_config(name)
    except KeyError:
        raise HTTPException(404, f"등록되지 않은 설정: {name}")
    except ValueError as e:
        raise HTTPException(500, str(e))
    meta = appconfig.REGISTRY[name]
    return {"name": name, "title": meta["title"], "description": meta["description"],
            "path": str(appconfig.config_path(name)), "value": value}


@router.put("/config/{name}")
def put_config(name: str, body: ConfigPut, request: Request, db: Session = Depends(get_db)):
    try:
        value = appconfig.save_config(name, body.value)
    except KeyError:
        raise HTTPException(404, f"등록되지 않은 설정: {name}")
    except ValueError as e:
        raise HTTPException(400, f"설정 검증 실패: {e}")
    record(db, action="CONFIG_EDIT", actor_id=get_actor_id(db), entity_type="config",
           entity_id=None, detail={"name": name}, request=request)
    db.commit()
    return {"name": name, "value": value}
