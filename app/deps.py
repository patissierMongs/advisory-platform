"""공용 의존성."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .db import get_db  # noqa: F401  (라우터에서 재사용)
from .enums import UserRole
from .models import AppUser


def get_actor_id(db: Session) -> int | None:
    """감사 로그의 행위 주체 — 로그인한 관리자를 우선한다.

    시그니처를 유지해 35개 호출부를 손대지 않는다. 실제 주체는 인증 의존성이 요청마다
    설정하는 ContextVar 에서 읽는다(app/auth.py).

    폴백(활성 ANALYST 1명)은 남겨 둔다 — 익명 게시판 쓰기는 actor_id=None 을 명시적으로
    넘기므로 영향이 없고, 시드/백그라운드 경로가 NULL 주체를 남기는 것을 막는다.
    주의: ThreadPoolExecutor 로 넘긴 작업(advisories._run_extract)에는 ContextVar 가
    전파되지 않는다. 그런 경로에서 쓰려면 submit 시점에 값을 캡처해 넘겨야 한다.
    """
    from .auth import current_actor_id

    uid = current_actor_id()
    if uid is not None:
        return uid
    user = db.scalar(select(AppUser).where(AppUser.role == UserRole.ANALYST).limit(1))
    return user.id if user else None
