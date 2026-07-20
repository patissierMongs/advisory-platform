"""권고문 본문 → 영향 제품·버전 규칙 추출 (§개편 — 추출 엔진).

기존 시스템은 CVE 코드만 추출하고 제품·버전은 CVE DB 에 전적으로 의존했다.
이 모듈은 본문에서 '영향 제품 + 버전 범위'를 직접 추출해 관리자에게 제안한다.

설계 원칙(오탐 방지):
  · 버전은 제품 언급의 문맥 창(window) 안에서만 인식한다 — 문서 내 임의 숫자
    (날짜·문서번호·CVE 일련번호·퍼센트)가 버전으로 빨려 들어가지 않는다.
  · '이하/미만/이상/초과/~' 등 한국어 범위 구문을 규칙(lte/lt/gte/gt/range)으로 해석한다.
    보안권고문 특성상 "X 이하" 는 하위 버전 전체가 대상이므로 열거가 아닌 범위로 저장한다.
  · "X(이상)으로 업데이트" 류 조치권고 버전은 **영향 버전이 아니라 조치(fix) 버전**이다.
    영향 규칙에서 제외하고 fixed_version 으로 분리 저장하며, 명시적 영향 범위가 없으면
    {"lt": fix} 를 유도한다(fix 미만 전체가 취약).
  · 다중 제품 지원 — 한 권고문이 Apache·Tomcat·IIS·nginx 처럼 여러 제품을 다루면
    제품별로 독립 규칙을 만든다.
  · 사전 미등록 제품도 "<제품명> <버전> 이하" 패턴이면 저신뢰 제안으로 올린다.
"""
from __future__ import annotations

import re

from .normalize import (
    PRODUCT_ALIASES,
    _ALIAS_INDEX,
    _boundary_ok,
    _vendor_guard_ok,
    slugify,
)

# ── 버전 토큰 ──────────────────────────────────────────────────────────────
# v1.2.3 / 9.0 / 122.x / 2022 / 22H2  (CVE·날짜·문서번호는 후처리로 배제)
_VER_TOKEN = re.compile(
    r"(?<![0-9A-Za-z.])(v?\d+(?:\.\d+){0,3}(?:\.[xX*])?|\d{2}[Hh]\d)(?![0-9])"
)

# 날짜·문서번호·CVE·퍼센트 등 버전 아님 판정용 문맥 패턴
_CVE_BEFORE = re.compile(r"CVE[\s\-_]*(\d{4})?[\s\-_]*$", re.IGNORECASE)
_DOC_BEFORE = re.compile(r"제\s*$")
_DATE_AFTER = re.compile(r"^\s*[.\-/년월]\s*\d{1,2}")
_UNIT_AFTER = re.compile(r"^\s*(?:%|퍼센트|호|건|명|개|페이지|쪽|번지)")
_DATE_FULL = re.compile(r"^\d{4}[.\-/]\d{1,2}[.\-/]\d{1,2}")

# ── 범위/조치 구문 ─────────────────────────────────────────────────────────
_AFTER_LTE = re.compile(r"^\s*(?:버전\s*)?(?:이하|및\s*이전(?:\s*버전)?|이전\s*(?:모든\s*)?버전|and\s+(?:earlier|prior|below)|or\s+earlier)", re.IGNORECASE)
_AFTER_LT = re.compile(r"^\s*(?:버전\s*)?미만", re.IGNORECASE)
_AFTER_GTE = re.compile(r"^\s*(?:버전\s*)?이상", re.IGNORECASE)
_AFTER_GT = re.compile(r"^\s*(?:버전\s*)?초과", re.IGNORECASE)
_BEFORE_LT = re.compile(r"(?:prior\s+to|before|earlier\s+than)\s*$", re.IGNORECASE)
_RANGE_SEP = re.compile(r"^\s*[~∼〜–—]\s*|^\s*(?:부터|에서)\s*$")

# 조치(fix) 버전 구문 — 버전 토큰 뒤에 이런 표현이 오면 '영향'이 아니라 '조치 권고'다.
_FIX_AFTER_STRICT = re.compile(
    r"^\s*(?:버전\s*)?(?:이상\s*)?(?:버전\s*)?(?:으로|로)\s*(?:업데이트|업그레이드|패치|갱신|교체|적용)"
    r"|^\s*(?:버전)?\s*(?:에서|버전에서)\s*(?:수정|해결|패치)", re.IGNORECASE)
_FIX_BEFORE = re.compile(
    r"(?:update\s+to|upgrade\s+to|fixed\s+in|최신\s*버전\s*\(?|조치\s*버전\s*[:：]?\s*|권장\s*버전\s*[:：]?\s*)\s*$",
    re.IGNORECASE)

# 창(window) 크기 — 제품 언급 이후 이 범위 안의 버전만 그 제품 것으로 본다.
_WINDOW = 160

# 자유 텍스트 제품 '발견' 시, 흔한 일반명사 별칭은 버전 증거 없이는 제안하지 않는다.
# ("한글"은 한국어 텍스트 어디에나 등장 — 버전 문맥 없이 제품으로 올리면 전부 오탐)
_DISCOVERY_NEEDS_VERSION = frozenset({
    "한글", "hwp", "한컴", "오피스", "office", "edge", "엣지", "linux", "windows server",
})

# 미등록 제품 제안 패턴: "<라틴 제품명> <버전> 이하/미만/이상" (범위 구문 필수 — 오탐 억제)
_UNKNOWN_PRODUCT = re.compile(
    r"(?<![A-Za-z0-9._-])([A-Z][A-Za-z0-9._+-]*(?:\s+[A-Z][A-Za-z0-9._+-]*){0,2})"
    r"\s+v?(\d+(?:\.\d+){0,3})\s*(이하|미만|이상|초과|및\s*이전)"
)


def _find_product_mentions(text: str) -> list[dict]:
    """사전 기반 제품 언급 탐색(토큰 경계·벤더 가드·최장일치·중복 구간 제거)."""
    low = text.lower()
    taken: list[tuple[int, int]] = []
    out: list[dict] = []
    for alias, key in _ALIAS_INDEX:      # 길이 내림차순 — 최장일치 우선
        start = 0
        while True:
            i = low.find(alias, start)
            if i == -1:
                break
            end = i + len(alias)
            start = i + 1
            if not _boundary_ok(low, i, end):
                continue
            if not _vendor_guard_ok(alias, low, end):
                continue
            if any(not (end <= s or i >= e) for s, e in taken):
                continue                 # 더 긴 별칭이 이미 차지한 구간
            taken.append((i, end))
            out.append({"key": key, "alias": alias, "name": text[i:end], "start": i, "end": end})
    out.sort(key=lambda m: m["start"])
    return out


def _is_noise_version(text: str, m: re.Match) -> bool:
    """버전 후보가 날짜·문서번호·CVE 일련번호·단위 수치인지 판정."""
    before = text[max(0, m.start() - 12):m.start()]
    after = text[m.end():m.end() + 12]
    tok = m.group(1)
    if _CVE_BEFORE.search(before):
        return True                       # CVE-2026-1234 의 연도/일련번호
    if _DOC_BEFORE.search(before):
        return True                       # "제2026-…호" 문서번호
    if _UNIT_AFTER.match(after):
        return True                       # 30%, 제12호, 3건 …
    if re.fullmatch(r"\d{4}", tok) and _DATE_AFTER.match(after):
        return True                       # 2026.6.26 / 2026년 …
    if _DATE_FULL.match(text[m.start():m.start() + 12]):
        return True
    if before.rstrip().endswith(("-", "–")) and re.search(r"\d{4}$", before.rstrip()[:-1].rstrip()):
        return True                       # 2026-0612 류 일련번호의 뒷부분
    return False


def _norm_ver(tok: str) -> str:
    tok = tok.strip()
    if tok[:1] in ("v", "V") and len(tok) > 1 and tok[1].isdigit():
        tok = tok[1:]
    return tok


def _scan_window(text: str, win_start: int, win_end: int) -> dict:
    """제품 문맥 창에서 버전 토큰을 분류해 (영향 규칙, fix 버전, 근거) 산출."""
    window = text[win_start:win_end]
    rule_ops: dict[str, str] = {}
    enum: list[str] = []
    range_pair: list[str] | None = None
    fixed: str | None = None
    pending_range_lo: str | None = None

    for m in _VER_TOKEN.finditer(window):
        abs_m_start = win_start + m.start()
        if _is_noise_version(text, _shift_match(m, text, abs_m_start)):
            continue
        tok = _norm_ver(m.group(1))
        before = window[max(0, m.start() - 24):m.start()]
        after = window[m.end():m.end() + 40]

        # ① 조치(fix) 버전 — 영향 규칙에서 제외
        if _FIX_BEFORE.search(before) or _FIX_AFTER_STRICT.match(after):
            fixed = fixed or tok
            continue
        # "X 이상" 인데 바로 뒤에 업데이트류 동사가 오면 fix ("9.0.50 이상으로 업데이트")
        if _AFTER_GTE.match(after):
            rest = _AFTER_GTE.match(after)
            tail = after[rest.end():]
            if _FIX_AFTER_STRICT.match("으로 " + tail.lstrip()) or re.match(
                    r"^\s*(?:으로|로)?\s*(?:업데이트|업그레이드|패치|갱신|버전\s*업|적용)", tail):
                fixed = fixed or tok
                continue

        # ② 범위 구문
        if pending_range_lo is not None:
            range_pair = [pending_range_lo, tok]
            pending_range_lo = None
            continue
        if _RANGE_SEP.match(after):
            pending_range_lo = tok
            continue
        if _AFTER_LTE.match(after):
            rule_ops["lte"] = tok
            continue
        if _AFTER_LT.match(after):
            rule_ops["lt"] = tok
            continue
        if _AFTER_GT.match(after):
            rule_ops["gt"] = tok
            continue
        if _AFTER_GTE.match(after):
            rule_ops["gte"] = tok
            continue
        if _BEFORE_LT.search(before):
            rule_ops["lt"] = tok
            continue
        # ③ 열거(문맥 창 안의 단독 버전)
        if tok not in enum:
            enum.append(tok)

    # 규칙 조합 우선순위: 명시 범위쌍 > 비교연산 > fix 유도 > 열거 > 전체
    if range_pair:
        rule: object = {"range": range_pair}
        confidence = 0.9
    elif rule_ops:
        rule = dict(rule_ops)
        confidence = 0.9
    elif fixed:
        rule = {"lt": fixed}
        confidence = 0.75
    elif enum:
        rule = enum
        confidence = 0.7
    else:
        rule = "*"
        confidence = 0.4
    snippet = re.sub(r"\s+", " ", window).strip()[:160]
    return {"rule": rule, "fixed_version": fixed, "confidence": confidence, "snippet": snippet}


class _FakeMatch:
    __slots__ = ("_start", "_end", "_g")

    def __init__(self, start: int, end: int, g: str):
        self._start, self._end, self._g = start, end, g

    def start(self) -> int:
        return self._start

    def end(self) -> int:
        return self._end

    def group(self, _i: int = 0) -> str:
        return self._g


def _shift_match(m: re.Match, text: str, abs_start: int) -> _FakeMatch:
    """창 내부 match 를 전체 텍스트 좌표로 옮긴 경량 래퍼(_is_noise_version 용)."""
    return _FakeMatch(abs_start, abs_start + (m.end() - m.start()), m.group(1))


def extract_products(text: str) -> list[dict]:
    """본문에서 영향 제품·버전 규칙 추출.

    반환: [{product_name, product_key, affected_versions, fixed_version,
            source_snippet, confidence}], product_key 중복 없음(병합).
    """
    if not text or not text.strip():
        return []
    mentions = _find_product_mentions(text)
    merged: dict[str, dict] = {}

    for idx, men in enumerate(mentions):
        win_start = men["end"]
        win_end = min(len(text), win_start + _WINDOW)
        if idx + 1 < len(mentions):
            win_end = min(win_end, mentions[idx + 1]["start"])
        info = _scan_window(text, win_start, win_end)

        # 일반명사 별칭은 버전 증거 없으면 제안하지 않는다(오탐 억제).
        if info["rule"] == "*" and men["alias"] in _DISCOVERY_NEEDS_VERSION:
            continue

        cur = merged.get(men["key"])
        if cur is None:
            merged[men["key"]] = {
                "product_name": men["name"],
                "product_key": men["key"],
                "affected_versions": info["rule"],
                "fixed_version": info["fixed_version"],
                "source_snippet": (men["name"] + " " + info["snippet"]).strip()[:200],
                "confidence": info["confidence"],
            }
        else:
            # 더 구체적인(신뢰 높은) 규칙으로 갱신, 열거는 합집합.
            if info["confidence"] > cur["confidence"]:
                cur["affected_versions"] = info["rule"]
                cur["confidence"] = info["confidence"]
                cur["source_snippet"] = (men["name"] + " " + info["snippet"]).strip()[:200]
            elif (isinstance(cur["affected_versions"], list)
                  and isinstance(info["rule"], list)):
                for v in info["rule"]:
                    if v not in cur["affected_versions"]:
                        cur["affected_versions"].append(v)
            cur["fixed_version"] = cur["fixed_version"] or info["fixed_version"]

    # 사전 미등록 제품 제안 — "<라틴 제품명> <버전> 이하" 명시 범위 구문만(저신뢰).
    known_spans = [(m["start"], m["end"]) for m in mentions]
    for um in _UNKNOWN_PRODUCT.finditer(text):
        s, e = um.start(1), um.end(1)
        if any(not (e <= ks or s >= ke) for ks, ke in known_spans):
            continue
        name = um.group(1).strip()
        if name.upper().startswith("CVE") or len(name) < 3:
            continue
        key = slugify(name)
        if not key or key in merged:
            continue
        ver, kw = um.group(2), um.group(3)
        op = {"이하": "lte", "미만": "lt", "이상": "gte", "초과": "gt"}.get(kw.strip(), "lte")
        merged[key] = {
            "product_name": name,
            "product_key": key,
            "affected_versions": {op: ver},
            "fixed_version": None,
            "source_snippet": re.sub(r"\s+", " ", text[max(0, s - 10):um.end() + 10]).strip()[:200],
            "confidence": 0.5,
        }

    return list(merged.values())
