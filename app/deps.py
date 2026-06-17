"""공용 의존성."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db  # noqa: F401  (라우터에서 재사용)
from .enums import UserRole
from .models import AppUser


def get_actor_id(db: Session) -> int | None:
    """단일 운영자 모델(§1.3): 활성 ANALYST 1명을 행위 주체로 사용."""
    user = db.scalar(select(AppUser).where(AppUser.role == UserRole.ANALYST).limit(1))
    return user.id if user else None
