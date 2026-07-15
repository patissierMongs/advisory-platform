"""CVE 게이트 보조 추출 — DB 미등록 CVE 수동 등록 폼의 기본값과 PDF 하이라이트 용어.

카탈로그 설정 파일(product_catalog)의 제품 패턴·버전 패턴을 본문에 적용한다.
· 제품/버전/날짜 자동 매칭 결과는 폼 기본값(선택 — 빈칸 가능)으로 제공.
· 매칭된 문자열은 카테고리별 색과 함께 반환 — STEP2 PDF 뷰어가 같은 색으로
  강조하므로, 폼(근거 칩)과 PDF 영역의 색이 항상 동일하다(§요구).
"""
from __future__ import annotations

import re
from datetime import date

from . import appconfig
from .extract import CVE_RE, _DATE_RE

_WINDOW = 400          # CVE 언급 주변에서 제품·버전을 찾는 창(±문자)
_MAX_TERMS_PER_CAT = 20  # PDF 하이라이트 용어 상한(과다 강조 방지)

_DATE_ANY = re.compile(_DATE_RE)
_DATE_LABELED = re.compile(r"(?:발표|게시|작성|배포|공고)\s*일?\s*[:：]?\s*" + _DATE_RE)


def _compile(p: str) -> re.Pattern | None:
    try:
        return re.compile(p, re.IGNORECASE)
    except re.error:
        return None


def _mask_cves(text: str) -> str:
    """CVE 코드 구간을 공백으로 마스킹 — 버전 패턴(연도 등)이 CVE 일련번호를 오탐하지 않게."""
    return CVE_RE.sub(lambda m: " " * (m.end() - m.start()), text)


def _iso(m: re.Match) -> str | None:
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3))).isoformat()
    except ValueError:
        return None


def analyze(text: str, cve_codes: list[str], catalog: dict | None = None) -> dict:
    """본문 분석 — 문서 수준 제품/버전/날짜 매칭 + CVE 코드별 제안 값.

    반환:
      colors: 카테고리별 색(cve·version·date + 제품별 color)
      products: [{key,label,color,terms[]}]  문서에서 매칭된 제품(등장 순)
      versions: [str]                        문서에서 매칭된 버전 표기(등장 순)
      dates:    [str]                        본문 날짜 표기(등장 순, ISO 아님 — 원문 그대로)
      items: {code: {product_key, product_label, versions[], published_at}}
      highlight_terms: [{term, category, color}]  PDF 하이라이트 용어
    """
    catalog = catalog or appconfig.get_config("product_catalog")
    colors = dict(catalog.get("colors", {}))
    colors.setdefault("cve", "#e8a33d")
    colors.setdefault("version", "#7a5a9a")
    colors.setdefault("date", "#2e9e5b")

    t = text or ""
    masked = _mask_cves(t)

    # ── 제품 매칭(문서 수준) — 제품별 첫 등장 위치·매칭 문자열들 ──
    products: list[dict] = []
    prod_spans: list[tuple[int, int, str]] = []   # (start, end, key) — 버전 창 판단에 사용
    for prod in catalog.get("products", []):
        key, label = prod.get("key"), prod.get("label")
        color = prod.get("color") or "#5a6b86"
        terms: list[str] = []
        first = None
        for p in prod.get("patterns", []):
            rx = _compile(p)
            if rx is None:
                continue
            for m in rx.finditer(masked):
                s = m.group(0).strip()
                if not s:
                    continue
                if first is None or m.start() < first:
                    first = m.start()
                prod_spans.append((m.start(), m.end(), key))
                if s not in terms:
                    terms.append(s)
        if terms:
            products.append({"key": key, "label": label, "color": color,
                             "first": first, "terms": terms[:_MAX_TERMS_PER_CAT]})
    products.sort(key=lambda x: x["first"])
    for p in products:
        p.pop("first", None)

    # ── 버전 매칭(문서 수준) — 등장 순, 중복 제거. 날짜 표기와 겹치는 매칭은 제외
    #    (2026.7.1 같은 날짜가 버전 후보로 섞이는 오탐 방지 — 날짜는 날짜 카테고리로만).
    date_spans = [(m.start(), m.end()) for m in _DATE_ANY.finditer(t)]

    def _in_date(s: int, e: int) -> bool:
        return any(a < e and s < b for a, b in date_spans)

    ver_hits: list[tuple[int, str]] = []
    for vp in catalog.get("version_patterns", []):
        rx = _compile(str(vp.get("pattern", "")))
        if rx is None:
            continue
        for m in rx.finditer(masked):
            if _in_date(m.start(), m.end()):
                continue
            ver_hits.append((m.start(), m.group(0)))
    ver_hits.sort(key=lambda h: h[0])
    versions: list[str] = []
    for _pos, s in ver_hits:
        if s not in versions:
            versions.append(s)

    # ── 날짜 — 라벨(발표일 등) 우선, 없으면 본문 첫 날짜 ──
    dates: list[str] = []
    published_at: str | None = None
    m = _DATE_LABELED.search(t)
    if m:
        published_at = _iso(m)
        dates.append(m.group(0).strip())
    for dm in _DATE_ANY.finditer(t):
        s = dm.group(0).strip()
        if published_at is None:
            published_at = _iso(dm)
        if s not in dates:
            dates.append(s)
        if len(dates) >= 5:
            break

    # ── CVE 코드별 제안 — 언급 주변 창에서 제품·버전을 좁혀 제안(없으면 문서 수준 폴백) ──
    items: dict[str, dict] = {}
    for code in cve_codes:
        window_ranges = [(max(0, mm.start() - _WINDOW), mm.end() + _WINDOW)
                         for mm in re.finditer(re.escape(code), t, re.IGNORECASE)]

        def _in_window(pos: int) -> bool:
            return any(a <= pos < b for a, b in window_ranges)

        near_keys: list[str] = []
        for s, _e, key in sorted(prod_spans):
            if _in_window(s) and key not in near_keys:
                near_keys.append(key)
        near_vers: list[str] = []
        for pos, s in ver_hits:
            if _in_window(pos) and s not in near_vers:
                near_vers.append(s)

        by_key = {p["key"]: p for p in products}
        pick = by_key.get(near_keys[0]) if near_keys else (products[0] if products else None)
        items[code] = {
            "product_key": pick["key"] if pick else None,
            "product_label": pick["label"] if pick else None,
            "versions": (near_vers or versions)[:6],
            "published_at": published_at,
        }

    # ── PDF 하이라이트 용어(카테고리별 색) ──
    highlight_terms: list[dict] = []
    for p in products:
        for s in p["terms"]:
            highlight_terms.append({"term": s, "category": "product", "color": p["color"]})
    for s in versions[:_MAX_TERMS_PER_CAT]:
        highlight_terms.append({"term": s, "category": "version", "color": colors["version"]})
    for s in dates[:3]:
        highlight_terms.append({"term": s, "category": "date", "color": colors["date"]})

    return {"colors": colors, "products": products, "versions": versions, "dates": dates,
            "items": items, "highlight_terms": highlight_terms}
