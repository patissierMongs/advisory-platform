"""오탐 제외 기억 (§★★★).

오탐으로 제외한 (자산, 제품군) 조합을 저장해 두고, 다음 권고문 매칭에서 동일 조합을
'제외 제안(suggested_exclude)'으로 표시한다. 관제 1인의 반복 작업을 줄인다.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ExclusionRule


def remember(db: Session, asset_id: int, product_key: str, reason: str | None, actor_id: int | None) -> None:
    if not product_key:
        return
    rule = db.scalar(
        select(ExclusionRule).where(
            ExclusionRule.asset_id == asset_id, ExclusionRule.product_key == product_key
        )
    )
    if rule:
        rule.is_active = True
        rule.reason = reason or rule.reason
    else:
        db.add(ExclusionRule(asset_id=asset_id, product_key=product_key,
                             reason=reason, created_by=actor_id, is_active=True))


def forget(db: Session, asset_id: int, product_key: str) -> None:
    rule = db.scalar(
        select(ExclusionRule).where(
            ExclusionRule.asset_id == asset_id, ExclusionRule.product_key == product_key
        )
    )
    if rule:
        rule.is_active = False


def active_pairs(db: Session) -> set[tuple[int, str]]:
    return {
        (r.asset_id, r.product_key)
        for r in db.scalars(select(ExclusionRule).where(ExclusionRule.is_active.is_(True)))
    }


def list_rules(db: Session) -> list[dict]:
    rows = db.scalars(select(ExclusionRule).where(ExclusionRule.is_active.is_(True))).all()
    return [
        {
            "id": r.id, "asset_id": r.asset_id,
            "asset_no": r.asset.asset_no if r.asset else None,
            "product_key": r.product_key, "reason": r.reason,
        }
        for r in rows
    ]
