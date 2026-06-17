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
    return str(raw).strip()


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


def _cmp(a: str, b: str) -> int:
    oa, ob = version_ordinal(a), version_ordinal(b)
    if oa is None or ob is None:
        raise CompareUndecidable(f"{a!r} vs {b!r}")
    # 길이가 다른 튜플은 짧은 쪽을 0으로 패딩.
    n = max(len(oa), len(ob))
    oa += (0,) * (n - len(oa))
    ob += (0,) * (n - len(ob))
    return (oa > ob) - (oa < ob)


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

    # 전체 버전
    if rule in (None, "*", "", []):
        return True, False

    # 자산 버전 미상 → 버전 한정 규칙엔 보수적 후보(사람 검토). 자산대장 버전 누락이 흔함.
    if not av:
        return True, True

    # 열거 목록
    if isinstance(rule, list):
        norm = {normalize_version(x).lower() for x in rule}
        return (av.lower() in norm), False

    if isinstance(rule, dict):
        try:
            if "range" in rule and isinstance(rule["range"], (list, tuple)) and len(rule["range"]) == 2:
                lo, hi = rule["range"]
                return (_cmp(av, lo) >= 0 and _cmp(av, hi) <= 0), False
            for op, fn in (
                ("lt", lambda c: c < 0),
                ("lte", lambda c: c <= 0),
                ("gt", lambda c: c > 0),
                ("gte", lambda c: c >= 0),
                ("eq", lambda c: c == 0),
            ):
                if op in rule:
                    return fn(_cmp(av, str(rule[op]))), False
        except CompareUndecidable:
            return True, True  # 보수적: 후보로 표기
        # 알 수 없는 dict 규칙 → 보수적 후보
        return True, True

    # 알 수 없는 형식 → 보수적 후보
    return True, True
