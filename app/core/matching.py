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


def cve_product_rules(cve: Cve) -> list[tuple[str, object]]:
    """CVE 의 (product_key, 영향버전 규칙) 목록 — 다중 제품 지원(§개편).

    primary(product_key/affected_versions) + affected_products(JSON 목록)를 합친다.
    HTTP 취약점처럼 Apache·Tomcat·IIS·nginx 여러 제품이 한 CVE 에 걸리는 경우
    제품별 규칙이 각각 매칭에 참여한다.
    """
    rules: list[tuple[str, object]] = []
    if cve.product_key:
        rules.append((cve.product_key, cve.affected_versions))
    for extra in (cve.affected_products or []):
        key = (extra or {}).get("product_key")
        if key and all(k != key for k, _ in rules):
            rules.append((key, (extra or {}).get("affected_versions")))
    return rules


def asset_matches_cve(asset: Asset, cve: Cve) -> tuple[bool, dict | None]:
    """단일 자산 ↔ CVE 매칭 판정. 근거(reason) 동봉.

    자산 버전은 정규화값(version_norm)과 원본(version_raw) 둘 다로 판정한다.
    정규화가 과하게 변형되어(예: "2021" → "21.001.20155") CVE 영향버전 목록과
    어긋나는 경우 취약 자산을 놓치지 않도록(보안 도구: 누락 < 오탐) — 둘 중 하나라도
    규칙을 만족하면 매칭. 관리자 화면(클라이언트 매칭)과 서버 저장 결과의 불일치도 해소.
    CVE 가 여러 제품에 걸치면(affected_products) 자산 제품키에 해당하는 규칙으로 판정.
    """
    for product_key, rule in cve_product_rules(cve):
        if asset.product_key != product_key:
            continue
        matched_n, cand_n = version_matches(asset.version_norm, rule)
        matched_r, cand_r = version_matches(asset.version_raw, rule)
        if not (matched_n or matched_r):
            continue
        # 둘 중 '확정 매칭'(matched & not candidate)이 하나라도 있으면 확정, 아니면 후보(사람 검토).
        confident = (matched_n and not cand_n) or (matched_r and not cand_r)
        return True, {
            "product_key": product_key,
            "version_rule": rule,
            "asset_version": asset.version_norm,
            "asset_version_raw": asset.version_raw,
            "candidate": not confident,  # True=버전 비교 불가/원본으로만 일치 → 사람 검토 권장
        }
    return False, None


def run_matching(db: Session, advisory: Advisory, actor_id: int | None = None) -> dict:
    """advisory 의 FOUND CVE 들을 자산과 매칭. 멱등(upsert + stale 회수).

    반환: {"matched": 활성매칭수, "departments": 대상부서수, "candidates": 후보수,
           "retracted": 회수된 매칭수}
    """
    found_cves = [ac for ac in active_cves(advisory)
                  if ac.lookup_status == enums.LookupStatus.FOUND and ac.cve]

    # 관련 제품키 자산만 조회(인덱스 활용) — 다중 제품 규칙 전체 포함.
    product_keys = {key for ac in found_cves for key, _rule in cve_product_rules(ac.cve)}
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
    seen: set[tuple[int, int]] = set()   # 이번 실행에서 여전히 성립한 (CVE, 자산) 쌍
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
            seen.add(key)
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

    # 회수(§개편 후속): 피드 정정·CVE 삭제로 더 이상 성립하지 않는 기존 매칭 정리.
    # 손대지 않은 행(MATCHED + 미회신)만 삭제 — 오탐 제외(EXCLUDED)·회신 이력이 있는
    # 행은 감사 기록 보존을 위해 유지하되 근거에 stale 표시만 남긴다.
    retracted = 0
    for key, m in list(existing.items()):
        if key in seen:
            continue
        if m.status == enums.MatchStatus.MATCHED and m.ack_status == enums.AckStatus.NONE:
            db.delete(m)
            retracted += 1
        else:
            reason = dict(m.match_reason or {})
            if not reason.get("stale"):
                reason["stale"] = True
                m.match_reason = reason

    if advisory.status in (
        enums.AdvisoryStatus.EXTRACTED,
        enums.AdvisoryStatus.NEEDS_CVE_UPDATE,
    ):
        advisory.status = enums.AdvisoryStatus.MATCHED

    db.flush()
    return {"matched": active, "departments": len(dept_ids), "candidates": candidates,
            "suggested_exclude": suggested, "retracted": retracted}


def active_cves(advisory: Advisory) -> list[AdvisoryCve]:
    """소프트 삭제(§개편)를 제외한 유효 추출 CVE."""
    return [ac for ac in advisory.cves if not ac.is_deleted]


def all_cves_found(advisory: Advisory) -> bool:
    """발송/매칭 게이트: 미해소(NOT_FOUND) CVE 가 없는가.

    CVE 가 하나도 없는 권고문(일반 공지형)은 '미등록 CVE' 가 없으므로 게이트를 통과한다 —
    매칭은 0건으로 끝나고, 발송 게이트(NO_ACTIVE_MATCH)와 종결 처리로 이어진다.
    소프트 삭제된 CVE 는 게이트에서 제외한다.
    """
    return all(ac.lookup_status == enums.LookupStatus.FOUND for ac in active_cves(advisory))
