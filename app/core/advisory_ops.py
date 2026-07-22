"""권고문 파생 데이터 운영 로직(§개편 후속).

  · refresh_extracted_products — 본문 → 영향 제품 제안 갱신(관리자 이력 보존)
  · reindex_advisory          — 문서번호 중심 관리 인덱스(advisory_index) 재생성
  · rework_open_advisories    — 피드/사전 갱신 후 미완료 권고문 일괄 재추출·재매칭

routers/advisories 와 routers/cve_feeds 가 공유한다(피드 적용이 권고문 재작업을
트리거하므로 라우터 간 순환 import 를 피해 core 로 분리).
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums
from ..models import Advisory, AdvisoryIndex, AdvisoryProduct
from . import product_extract
from .matching import active_cves, run_matching
from .versioning import normalize_version  # noqa: F401  (규칙 표기 확장 대비)

# 재작업 대상에서 제외 — 종결 상태 + 업로드/추출 진행 중(백그라운드 추출 워커와
# 같은 advisory_product 행을 동시에 지웠다 넣으면 unique 충돌·중복 제안이 난다.
# 진행 중 권고문은 자기 워커가 끝나며 최신 사전으로 추출·색인하므로 건너뛰어도 결과 동일).
_SKIP_REWORK = (enums.AdvisoryStatus.COMPLETED, enums.AdvisoryStatus.ARCHIVED,
                enums.AdvisoryStatus.UPLOADED, enums.AdvisoryStatus.EXTRACTING)


def refresh_extracted_products(db: Session, adv: Advisory, text: str,
                               *, revive_deleted: bool) -> int:
    """본문에서 제품·버전 추출 → advisory_product 갱신(§개편).

    · 이전 '추출 제안'(origin=EXTRACTED, status=SUGGESTED)은 새 결과로 교체.
    · CONFIRMED(관리자 확인)·MANUAL(수동 추가)은 유지.
    · DELETED 는 revive_deleted=False 면 유지(재추출로 되살아나지 않음 — 자동 재추출),
      True 면 다시 SUGGESTED 로 복원(관리자가 '수동 재추출'로 명시 요청한 경우).
    반환: 제안 건수.
    """
    extracted = product_extract.extract_products(text)
    keep_keys: set[str] = set()
    for p in list(adv.products):
        if p.status == "DELETED" and revive_deleted and p.origin == "EXTRACTED":
            db.delete(p)          # 곧바로 새 제안으로 재생성
            continue
        if p.origin == "EXTRACTED" and p.status == "SUGGESTED":
            db.delete(p)          # 이전 제안 → 새 결과로 교체
            continue
        keep_keys.add(p.product_key)
    db.flush()
    n = 0
    for item in extracted:
        if item["product_key"] in keep_keys:
            continue              # 관리자 확인/수동/삭제 이력이 우선
        db.add(AdvisoryProduct(
            advisory=adv,
            product_name=item["product_name"],
            product_key=item["product_key"],
            affected_versions=item["affected_versions"],
            fixed_version=item.get("fixed_version"),
            source_snippet=item.get("source_snippet"),
            confidence=item.get("confidence"),
            status="SUGGESTED",
            origin="EXTRACTED",
        ))
        n += 1
    return n


def _versions_text(rule) -> str:
    """영향버전 규칙 → 검색·표시용 짧은 텍스트."""
    if rule in (None, "*", "", []):
        return "전체"
    if isinstance(rule, list):
        return ", ".join(str(v) for v in rule)
    if isinstance(rule, dict):
        rng = rule.get("range")
        if rng is not None:
            # 방어: API 로 임의 object 가 들어올 수 있어 형태 검증(색인 전체 중단 방지)
            if isinstance(rng, (list, tuple)) and len(rng) >= 2:
                return f"{rng[0]}~{rng[1]}"
            return str(rng)
        parts = []
        for op, label in (("gte", "이상"), ("gt", "초과"), ("lte", "이하"), ("lt", "미만"), ("eq", "")):
            if op in rule:
                parts.append(f"{rule[op]}{label}")
        return " ".join(parts) or str(rule)
    return str(rule)


def reindex_advisory(db: Session, adv: Advisory) -> AdvisoryIndex:
    """권고문 1건의 관리 인덱스(advisory_index) 재생성 — 멱등 upsert(§개편 후속).

    문서번호·CVE 목록·대상 제품(권고문 추출/수동 + CVE DB 조회 결과의 합집합)·
    버전·날짜·배포기관을 집약하고, 전 필드를 search_text 로 평탄화한다.
    """
    db.flush()   # 대기 중 변경을 확정 — 컬렉션 접근 전 최신화 보장
    cves = [ac.cve_id_text for ac in active_cves(adv)]
    products: list[dict] = []
    seen_keys: set[str] = set()
    # adv.products 컬렉션은 session.delete 된 행을 flush 후에도 들고 있다(SQLAlchemy 는
    # 로드된 컬렉션을 자동 정리하지 않음) → 재추출 직후 옛 제안이 색인에 섞이므로 DB 재조회.
    live_products = db.scalars(
        select(AdvisoryProduct).where(AdvisoryProduct.advisory_id == adv.id)).all()
    for p in live_products:
        if p.status == "DELETED":
            continue
        products.append({"name": p.product_name, "key": p.product_key,
                         "versions": _versions_text(p.affected_versions)})
        seen_keys.add(p.product_key)
    for ac in active_cves(adv):
        c = ac.cve
        if not c:
            continue
        extra = [e for e in (c.affected_products or []) if isinstance(e, dict)]  # 피드 미검증 방어
        for key, name, rule in (
            [(c.product_key, c.product_name, c.affected_versions)]
            + [(e.get("product_key"), e.get("product_name"), e.get("affected_versions"))
               for e in extra]
        ):
            if not key or key in seen_keys:
                continue
            products.append({"name": name or key, "key": key, "versions": _versions_text(rule)})
            seen_keys.add(key)

    hay = " ".join(filter(None, (
        adv.doc_no, adv.title, adv.source_org,
        " ".join(cves),
        " ".join(p["name"] for p in products),
        " ".join(p["key"] for p in products),
        " ".join(p["versions"] for p in products),
    ))).lower()

    row = db.scalar(select(AdvisoryIndex).where(AdvisoryIndex.advisory_id == adv.id))
    if row is None:
        row = AdvisoryIndex(advisory_id=adv.id)
        db.add(row)
    row.doc_no = adv.doc_no
    row.source_org = adv.source_org
    row.received_at = adv.received_at
    row.due_at = adv.due_at
    row.cves = cves
    # NVD 다중 제품 CVE(수십~수백 CPE)로 행·목록 payload 가 비대해지지 않게 표시용은 상한.
    # search_text 는 전 제품을 포함하므로 검색 커버리지는 그대로다.
    row.products = products[:50]
    row.search_text = hay
    db.flush()
    return row


def rework_open_advisories(db: Session) -> dict:
    """피드/추출 사전 갱신 후 — 종결(완료·보관)·추출 진행 중 제외 전 권고문 재작업(§개편 후속).

    각 미완료 권고문에 대해:
      1) 본문 제품·버전 재추출(관리자 확인/수동/삭제 이력 보존)
      2) 매칭 단계 이후(MATCHED·NOTIFYING)면 자산 재매칭(upsert — 제외/회신 상태 보존)
      3) 관리 인덱스 재생성
    게시판·목록은 이 데이터를 읽으므로 다음 조회부터 즉시 반영된다.
    """
    advs = db.scalars(select(Advisory).where(Advisory.status.notin_(_SKIP_REWORK))).all()
    reextracted = rematched = 0
    for adv in advs:
        text = adv.extracted_text or ""
        if text.strip():
            refresh_extracted_products(db, adv, text, revive_deleted=False)
            reextracted += 1
        if adv.status in (enums.AdvisoryStatus.MATCHED, enums.AdvisoryStatus.NOTIFYING):
            run_matching(db, adv)
            rematched += 1
        reindex_advisory(db, adv)
    db.flush()
    return {"reworked": len(advs), "reextracted": reextracted, "rematched": rematched}
