"""감사 로그 헬퍼 (명세서 §3.10 / §7).

모든 변경 작업(업로드·피드 적용·오탐 제외·발송 등)에 행위 주체·시각·IP를 기록한다.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .models import AuditLog


def record(
    db: Session,
    *,
    action: str,
    actor_id: int | None = None,
    entity_type: str | None = None,
    entity_id: int | None = None,
    detail: dict | None = None,
    request=None,
) -> AuditLog:
    ip = ua = None
    if request is not None:
        ip = getattr(getattr(request, "client", None), "host", None)
        ua = request.headers.get("user-agent") if hasattr(request, "headers") else None
    log = AuditLog(
        actor_id=actor_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        detail=detail,
        ip=ip,
        user_agent=ua,
    )
    db.add(log)
    return log
