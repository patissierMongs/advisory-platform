"""버전 정규화·비교 및 영향버전 규칙 해석 (명세서 §4.6-2).

제품군마다 버전 체계가 다르다:
  - Windows feature update : "23H2"  → (2023, 2)
  - Office/한컴 연도        : "2021"  → (2021,)
  - Chrome semver          : "124", "122.x" → (124,) / (122,)
  - Acrobat                : "DC 2022" → (2022,)
같은 product_key 내에서만 비교하므로 체계가 일치한다고 가정하되,
비교 불가 시 보수적으로 '후보(candidate)'로 표기해 사람 검토로 넘긴다.
"""
from __future__ import annotations

import re

_YYHN = re.compile(r"^\s*(\d{2})\s*h\s*(\d)\s*$", re.IGNORECASE)  # 23H2
_NUMS = re.compile(r"\d+")


def normalize_version(raw: str | None) -> str:
    if raw is None:
        return ""
    s = str(raw).strip()
    # 'v124.0' 같은 접두 표기는 흔한 자산대장 관례 — 열거 규칙의 문자열 비교가 어긋나지 않게 제거.
    if re.match(r"^[vV]\d", s):
        s = s[1:]
    return s


def version_ordinal(v: str | None) -> tuple[int, ...] | None:
    """버전 문자열 → 비교 가능한 정수 튜플. 추출 불가 시 None."""
    if not v:
        return None
    s = str(v).strip()
    m = _YYHN.match(s)
    if m:
        return (2000 + int(m.group(1)), int(m.group(2)))
    if "dc" in s.lower():
        year = re.search(r"(19|20)\d{2}", s)
        if year:
            return (int(year.group(0)),)
    nums = _NUMS.findall(s)  # "122.x" → ["122"], "10.0.19045" → [10,0,19045]
    if nums:
        return tuple(int(n) for n in nums)
    return None


class CompareUndecidable(Exception):
    """버전 비교 체계가 달라 판정 불가 — 보수적으로 후보 처리."""


# 선두 성분이 이 값 이상이면 '연도형' 버전으로 본다(2019·2021, 그리고 22H2→2022).
# 통상 semver/빌드 major(Chrome 124, Windows '10.0.x' 의 10 …)는 이보다 훨씬 작다.
# 한쪽만 연도형이면 서로 다른 버전 체계라 확신 비교가 불가능하다(§매칭 정확성 수정).
_YEAR_MIN = 1000


def _relation(a: str, b: str) -> tuple[int, str]:
    """두 버전을 '공통 자릿수(prefix)'로 비교. 반환 (sign, mode).

    sign : 공통 prefix 비교 결과 -1/0/1.
    mode : sign==0 일 때만 의미.
      'exact'        정확히 같은 자릿수까지 동일 (예: 2.4.57 vs 2.4.57)
      'asset_within' 규칙 경계가 더 굵어(짧아) 자산이 그 계열 '안'에 있음
                     (예: 규칙 '124', 자산 '124.0.6367.91' → 124 계열 내부)
      'undecidable'  자산이 규칙보다 덜 구체적 → 남은 자릿수를 알 수 없어 판정 불가
                     (예: 규칙 '10.0.19045.4291', 자산 '10.0.19045')

    zero-padding(옛 _cmp) 방식은 굵은 경계('124 이하')를 '124.0.0.0' 으로 오해해
    124.x 자산을 확신-미탐시켰다. prefix 비교로 그 결함을 없앤다.
    """
    oa, ob = version_ordinal(a), version_ordinal(b)
    if oa is None or ob is None:
        raise CompareUndecidable(f"{a!r} vs {b!r}")
    # 체계 불일치(연도형 ↔ semver/빌드) — 자릿수를 맞춰도 의미가 없다 → 후보로.
    if (oa[0] >= _YEAR_MIN) != (ob[0] >= _YEAR_MIN):
        raise CompareUndecidable(f"scheme mismatch: {a!r} vs {b!r}")
    k = min(len(oa), len(ob))
    pa, pb = oa[:k], ob[:k]
    if pa < pb:
        return -1, "exact"
    if pa > pb:
        return 1, "exact"
    if len(oa) == len(ob):
        return 0, "exact"
    if len(ob) < len(oa):
        return 0, "asset_within"   # 규칙 경계가 더 굵음 → 자산이 그 계열 내부
    return 0, "undecidable"        # 자산이 덜 구체적 → 판정 불가


def _eval_op(op: str, av: str, bv: str) -> tuple[bool, bool]:
    """단일 비교 연산(lt/lte/gt/gte/eq) 평가 → (matched, is_candidate).

    경계 포함(이하/이상)은 '자산이 경계 계열 내부'(asset_within)일 때도 매칭,
    엄격 비교(미만/초과)는 내부일 때 미매칭. 자산이 덜 구체적이면(undecidable)
    누락을 피하려 보수적 후보(True, True)로 넘긴다.
    """
    sign, mode = _relation(av, bv)   # CompareUndecidable 은 호출측에서 후보 처리
    if mode == "undecidable":
        return True, True
    inclusive_tie = sign == 0 and mode in ("exact", "asset_within")
    if op == "lt":
        return sign < 0, False
    if op == "lte":
        return sign < 0 or inclusive_tie, False
    if op == "gt":
        return sign > 0, False
    if op == "gte":
        return sign > 0 or inclusive_tie, False
    if op == "eq":
        if sign != 0:
            return False, False
        return (mode == "exact"), (mode != "exact")
    return True, True


def version_matches(asset_version: str | None, rule) -> tuple[bool, bool]:
    """자산 버전이 CVE 영향버전 규칙(rule)에 해당하는지 판정.

    rule 형식(§4.6):
      ["22H2","23H2"]            열거
      {"lt":"124"}               미만
      {"lte"/"gt"/"gte":...}     비교(확장)
      {"range":["DC2019","DC2023"]}  경계 포함 범위
      "*" | [] | None            전체(제품 키만 일치하면 매칭)

    반환: (matched, is_candidate)
      is_candidate=True 는 '비교 불가로 사람 검토 필요'한 보수적 후보.
    """
    av = normalize_version(asset_version)

    # 전체 버전 — 열거 목록에 '*' 가 섞여 온 경우(내부 피드 versions:"*" 등)도 동일.
    if rule in (None, "*", "", []):
        return True, False
    if isinstance(rule, list) and any(str(x).strip() == "*" for x in rule):
        return True, False

    # 자산 버전 미상 → 버전 한정 규칙엔 보수적 후보(사람 검토). 자산대장 버전 누락이 흔함.
    if not av:
        return True, True

    # 열거 목록
    if isinstance(rule, list):
        norm = {normalize_version(x).lower() for x in rule}
        if av.lower() in norm:
            return True, False
        ao = version_ordinal(av)
        if ao is None:
            # '알 수 없음' 등 해석 불가 텍스트 — dict 규칙과 동일하게 보수적 후보(사람 검토).
            # 문자열 불일치만으로 확정 미매칭 처리하면 취약 자산이 조용히 누락된다.
            return True, True
        # 표기만 다른 동일 버전('124.0' vs '124.0.6367.91' 아님 — 정확 서수 일치만) 재확인.
        for x in rule:
            if version_ordinal(normalize_version(x)) == ao:
                return True, False
        return False, False

    if isinstance(rule, dict):
        try:
            if "range" in rule and isinstance(rule["range"], (list, tuple)) and len(rule["range"]) == 2:
                lo, hi = rule["range"]
                lo_m, lo_c = _eval_op("gte", av, str(lo))   # 경계 포함
                hi_m, hi_c = _eval_op("lte", av, str(hi))
                matched = lo_m and hi_m
                return matched, matched and (lo_c or hi_c)
            # 복수 연산자 dict({"gte":A,"lte":B} 등)는 모든 조건의 AND 로 평가한다 —
            # 권고문 추출기가 "A 이상 B 이하" 를 이 형태로 저장한다(§개편).
            present = [op for op in ("lt", "lte", "gt", "gte", "eq") if op in rule]
            if present:
                results = [_eval_op(op, av, str(rule[op])) for op in present]
                matched = all(m for m, _ in results)
                # 하나라도 '비교 불가로 매칭'이면 확정이 아니라 후보(사람 검토).
                candidate = matched and any(c for _, c in results)
                return matched, candidate
        except CompareUndecidable:
            return True, True  # 보수적: 후보로 표기
        # 알 수 없는 dict 규칙 → 보수적 후보
        return True, True

    # 알 수 없는 형식 → 보수적 후보
    return True, True
