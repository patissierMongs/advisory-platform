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

from . import normalize as _nz
from .normalize import (
    PRODUCT_ALIASES,  # noqa: F401 — 하위 호환(외부 참조)
    _boundary_ok,
    _vendor_guard_ok,
    slugify,
)

# ── 버전 토큰 ──────────────────────────────────────────────────────────────
# v1.2.3 / 9.0 / 122.x / 2022 / 22H2  (CVE·날짜·문서번호는 후처리로 배제)
# 22H2 형태를 교대(alternation) 앞에 둔다 — 뒤에 두면 "22H2"가 "22"로 잘린다(§스트레스 S05).
_VER_TOKEN = re.compile(
    r"(?<![0-9A-Za-z.])(\d{2}[Hh]\d|v?\d+(?:\.\d+){0,3}(?:\.[xX*])?)(?![0-9])"
)

# 날짜·문서번호·CVE·퍼센트 등 버전 아님 판정용 문맥 패턴
_CVE_BEFORE = re.compile(r"CVE[\s\-_]*(\d{4})?[\s\-_]*$", re.IGNORECASE)
_DOC_BEFORE = re.compile(r"제\s*$")
_DATE_AFTER = re.compile(r"^\s*[.\-/년월]\s*\d{1,2}")
# 단위·날짜 접미어 — "6월"의 6, "3건"의 3 같은 수치가 버전으로 유입되는 것 차단(§스트레스 S05).
_UNIT_AFTER = re.compile(r"^\s*(?:%|퍼센트|호|건|명|개|페이지|쪽|번지|월|일|년|시|분|주|차|회)")
_DATE_FULL = re.compile(r"^\d{4}[.\-/]\d{1,2}[.\-/]\d{1,2}")

# ── 범위/조치 구문 ─────────────────────────────────────────────────────────
_AFTER_LTE = re.compile(r"^\s*(?:버전\s*)?(?:이하|및\s*이전(?:\s*버전)?|이전\s*(?:모든\s*)?버전|and\s+(?:earlier|prior|below)|or\s+earlier)", re.IGNORECASE)
_AFTER_LT = re.compile(r"^\s*(?:버전\s*)?미만", re.IGNORECASE)
_AFTER_GTE = re.compile(r"^\s*(?:버전\s*)?이상", re.IGNORECASE)
_AFTER_GT = re.compile(r"^\s*(?:버전\s*)?초과", re.IGNORECASE)
_BEFORE_LT = re.compile(r"(?:prior\s+to|before|earlier\s+than)\s*$", re.IGNORECASE)
# 물결형 범위 구분자("1.20 ~ 1.24").
_RANGE_TILDE = re.compile(r"^\s*[~∼〜–—]\s*")
# 영문 범위("8.1.0 to 8.1.2"). 한국어 권고문에도 영문 표가 흔히 섞여 들어온다.
# 이게 없으면 범위가 '정확 버전 열거'로 저장돼 경계 사이(8.1.1)의 취약 자산이 조용히
# 누락된다 — D1~D3 와 같은 '확신하는 오답' 계열이라 여기서 함께 막는다.
# 뒤에 버전 토큰이 이어질 때만 범위로 본다("~ 이후 별도 안내" 같은 문구에 오작동 방지).
_RANGE_TO_EN = re.compile(r"^\s*(?:to|through|thru|up\s+to)\s+(?=v?\d)", re.IGNORECASE)
# 한국어 범위 시작어("1.20.0 부터 …"). "부터/에서" 뒤에 상한 버전이 이어진다.
# 예전엔 `부터…$` 로 앵커돼 문장 중간의 "부터"를 못 잡아, 가장 흔한 "X 부터 Y 까지"
# 표현이 범위가 아니라 열거로 저장되는 확신-미탐 결함이 있었다(§매칭 정확성 수정).
_RANGE_FROM = re.compile(r"^\s*(?:부터|에서)\b|^\s*(?:부터|에서)\s")
# 범위 종료어 — "부터" 뒤에 이게 있으면 상한이 있는 범위, 없으면 단독 "이상"(gte)으로 본다.
_RANGE_TO = re.compile(r"까지")

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
    """사전 기반 제품 언급 탐색(토큰 경계·벤더 가드·최장일치·중복 구간 제거).

    큐레이션 사전을 먼저 훑고(안정·소규모), 피드 유래 동적 사전은 첫 토큰 버킷으로
    후보만 추려 검사한다 — NVD 급 수만 별칭에서도 본문 토큰 수에 비례하는 비용.
    동적 히트는 dynamic=True 로 표시되어 버전 문맥 없이는 제안되지 않는다.
    """
    low = text.lower()
    taken: list[tuple[int, int]] = []
    out: list[dict] = []

    def _scan(pairs, dynamic: bool) -> None:
        for alias, key in pairs:   # 길이 내림차순 — 최장일치 우선
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
                    continue                 # 더 긴/먼저 온(큐레이션) 별칭이 차지한 구간
                taken.append((i, end))
                out.append({"key": key, "alias": alias, "name": text[i:end],
                            "start": i, "end": end, "dynamic": dynamic})

    # 모듈 속성으로 매번 조회(§개편 후속) — 피드 동기화가 인덱스를 재구축해도 최신 사전 사용.
    _scan(_nz._ALIAS_INDEX, dynamic=False)
    dyn = _nz._DYNAMIC_BY_TOKEN
    if dyn:
        text_tokens = set(_nz._TOKEN_SPLIT.split(low))
        cands: list[tuple[str, str]] = []
        for t in text_tokens:
            if t and t in dyn:
                # 별칭의 모든 토큰이 본문에 있어야 부분일치 가능 — find 전 후보 축소.
                cands.extend((alias, key) for alias, key, toks in dyn[t]
                             if all(tk in text_tokens for tk in toks))
        cands.sort(key=lambda p: len(p[0]), reverse=True)
        _scan(cands, dynamic=True)

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
        if _RANGE_TILDE.match(after) or _RANGE_TO_EN.match(after):
            pending_range_lo = tok
            continue
        if _RANGE_FROM.match(after):
            # "X 부터 Y 까지" → 범위(다음 버전 토큰을 상한으로). "까지" 없이 "X 부터" 단독은
            # 상한이 없으므로 '이상(gte)'으로 해석한다.
            if _RANGE_TO.search(window[m.end():]):
                pending_range_lo = tok
            else:
                rule_ops["gte"] = tok
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


def _product_identity(cell: str) -> tuple[str, str] | None:
    """제품명 셀 → (표시명, product_key).

    별칭 사전을 먼저 태워 정식 키로 정규화한다("Microsoft Windows 11" → windows_11).
    사전에 없으면 slugify 로 떨어뜨린다 — 표에 적힌 제품을 사전에 없다고 버리면
    관리자가 그 권고문에 대상이 없다고 오해한다.
    """
    cell = (cell or "").strip()
    if not cell:
        return None
    mentions = _find_product_mentions(cell)
    if mentions:
        return mentions[0]["name"], mentions[0]["key"]
    key = slugify(cell)
    return (cell[:200], key) if key else None


def _fixed_versions(cell: str) -> list[str]:
    """해결 버전 셀 → 버전 문자열 목록. '9.0.90, 10.1.25' 같은 다중 표기를 그대로 살린다."""
    return [_norm_ver(m.group(1)) for m in _VER_TOKEN.finditer(cell or "")]


def _merge_rules(rules: list[object]) -> object:
    """한 제품의 여러 영향 규칙 → 단일 규칙.

    표는 같은 제품에 범위를 여러 줄로 적는데 AdvisoryProduct 는 제품당 1행이다.
    리스트로 담으면 '정확 버전 열거'로 오해되므로 any(OR) 형식을 쓴다(versioning.py 참조).
    """
    uniq: list[object] = []
    for r in rules:
        if r not in uniq:
            uniq.append(r)
    if not uniq:
        return "*"
    if "*" in uniq:
        return "*"          # 해석 불가가 하나라도 있으면 그게 상위집합 — 좁히면 자산을 놓친다
    if len(uniq) == 1:
        return uniq[0]
    return {"any": uniq}


def extract_products_from_table(rows) -> list[dict]:
    """복원된 표 행 → 영향 제품·버전 규칙. 반환 스키마는 extract_products 와 동일.

    버전 구문 해석은 새로 만들지 않고 _scan_window 를 셀 텍스트에 그대로 태운다 —
    "8.1.0 이상 8.1.2 미만"·"9.0.90 미만"·"3.0.0 ~ 3.0.14"·"22H2, 23H2" 전부 이미 처리된다.
    열 의미가 명시적이라 본문 스캔보다 신뢰도가 높다.
    """
    merged: dict[str, dict] = {}
    for row in rows:
        ident = _product_identity(getattr(row, "product", ""))
        if ident is None:
            continue
        name, key = ident
        affected = (getattr(row, "affected", "") or "").strip()
        info = _scan_window(affected, 0, len(affected)) if affected else {
            "rule": "*", "fixed_version": None, "confidence": 0.4, "snippet": ""}
        fixes = _fixed_versions(getattr(row, "fixed", ""))

        rule = info["rule"]
        # 범위별 해결버전은 규칙 안에 실어 둔다. _eval_op 는 비교 연산자 키만 보므로
        # 매칭에는 영향이 없고, 화면에서 '이 범위는 어디로 올려야 하나'를 보여줄 수 있다.
        if isinstance(rule, dict) and "any" not in rule and fixes:
            rule = dict(rule, fixed=", ".join(fixes))

        snippet = " · ".join(p for p in (getattr(row, "cve", ""), name, affected,
                                         getattr(row, "fixed", "")) if p)[:200]
        cur = merged.get(key)
        if cur is None:
            merged[key] = {
                "product_name": name,
                "product_key": key,
                "_rules": [rule],
                "_fixes": list(fixes),
                "source_snippet": snippet,
                "confidence": 0.95 if affected else 0.6,
            }
        else:
            cur["_rules"].append(rule)
            for f in fixes:
                if f not in cur["_fixes"]:
                    cur["_fixes"].append(f)

    out = []
    for item in merged.values():
        rules = item.pop("_rules")
        fixes = item.pop("_fixes")
        item["affected_versions"] = _merge_rules(rules)
        item["fixed_version"] = (", ".join(fixes))[:120] or None
        out.append(item)
    return out


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

        # 일반명사 별칭·피드 유래 동적 별칭은 버전 증거 없으면 제안하지 않는다(오탐 억제 —
        # NVD 제품명은 검증 안 된 자동 등재라 '*' 제안을 열면 모든 권고문에 잡음이 쌓인다).
        if info["rule"] == "*" and (
            men["alias"] in _DISCOVERY_NEEDS_VERSION or men.get("dynamic")
        ):
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
