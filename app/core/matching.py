"""매칭 알고리즘 (명세서 §4.6-3).

FOUND 상태인 advisory_cve × asset 곱집합에서 제품키+버전 규칙을 만족하는 쌍을
match 로 생성/갱신한다. (product_key, version_norm) 복합 인덱스를 활용.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums
from ..models import Advisory, AdvisoryCve, Asset, Cve, Match
from . import exclusions
from .versioning import version_matches


def asset_matches_cve(asset: Asset, cve: Cve) -> tuple[bool, dict | None]:
    """단일 자산 ↔ CVE 매칭 판정. 근거(reason) 동봉."""
    if not cve.product_key or asset.product_key != cve.product_key:
        return False, None
    matched, candidate = version_matches(asset.version_norm, cve.affected_versions)
    if not matched:
        return False, None
    return True, {
        "product_key": cve.product_key,
        "version_rule": cve.affected_versions,
        "asset_version": asset.version_norm,
        "candidate": candidate,  # True=버전 비교 불가로 사람 검토 권장
    }


def run_matching(db: Session, advisory: Advisory, actor_id: int | None = None) -> dict:
    """advisory 의 FOUND CVE 들을 자산과 매칭. 멱등(upsert).

    반환: {"matched": 활성매칭수, "departments": 대상부서수, "candidates": 후보수}
    """
    found_cves = [ac for ac in advisory.cves if ac.lookup_status == enums.LookupStatus.FOUND and ac.cve]

    # 관련 제품키 자산만 조회(인덱스 활용).
    product_keys = {ac.cve.product_key for ac in found_cves if ac.cve.product_key}
    assets: list[Asset] = []
    if product_keys:
        assets = list(
            db.scalars(
                select(Asset).where(
                    Asset.product_key.in_(product_keys),
                    Asset.status != enums.AssetStatus.RETIRED,
                )
            )
        )

    # 기존 매칭 인덱스(제외 상태 보존을 위해 upsert).
    existing = {
        (m.advisory_cve_id, m.asset_id): m
        for m in db.scalars(select(Match).where(Match.advisory_id == advisory.id))
    }
    excl_pairs = exclusions.active_pairs(db)  # 오탐 기억(§★★★)

    active = 0
    candidates = 0
    suggested = 0
    dept_ids: set[int] = set()
    for ac in found_cves:
        for asset in assets:
            ok, reason = asset_matches_cve(asset, ac.cve)
            if not ok:
                continue
            # 이전에 동일 (자산, 제품군)을 오탐 제외한 적 있으면 제외 제안 표시.
            if (asset.id, ac.cve.product_key) in excl_pairs:
                reason["suggested_exclude"] = True
                suggested += 1
            key = (ac.id, asset.id)
            m = existing.get(key)
            if m is None:
                m = Match(
                    advisory_id=advisory.id,
                    advisory_cve_id=ac.id,
                    asset_id=asset.id,
                    match_reason=reason,
                    status=enums.MatchStatus.MATCHED,
                )
                db.add(m)
                existing[key] = m
            else:
                m.match_reason = reason  # 근거 갱신, 제외 상태는 유지
            if reason and reason.get("candidate"):
                candidates += 1
            if m.status == enums.MatchStatus.MATCHED:
                active += 1
                dept_ids.add(asset.department_id)

    if advisory.status in (
        enums.AdvisoryStatus.EXTRACTED,
        enums.AdvisoryStatus.NEEDS_CVE_UPDATE,
    ):
        advisory.status = enums.AdvisoryStatus.MATCHED

    db.flush()
    return {"matched": active, "departments": len(dept_ids), "candidates": candidates,
            "suggested_exclude": suggested}


def all_cves_found(advisory: Advisory) -> bool:
    """발송/매칭 게이트: 추출된 모든 CVE 가 DB 조회 성공 상태인가."""
    if not advisory.cves:
        return False
    return all(ac.lookup_status == enums.LookupStatus.FOUND for ac in advisory.cves)
