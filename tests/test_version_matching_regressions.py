"""버전 매칭 정확성 회귀 — '확신하는 오답(confident false negative)' 고정.

코드 추적으로 확증된 결함 3종을 박제한다. 모두 취약 자산을 조용히 '해당 없음' 으로
판정하던(또는 범위를 열거로 오저장하던) 버그로, 보안 도구에서 가장 위험한 실패 모드다.
이 결함들은 추출 엔진(정규식→LLM) 교체와 무관한 '비교 계층' 의 결정론적 버그라,
입력이 완벽해도 재발할 수 있어 여기서 영구 고정한다.

  D1  굵은 상한 경계('124 이하')가 자기 계열(124.x)을 배제 — zero-padding 비교 결함.
  D2  서로 다른 버전 체계(Windows '22H2'/'2019' ↔ 빌드 '10.0.x')를 확신 비교 — 체계 오인.
  D3  가장 흔한 한국어 범위 표현 'X 부터 Y 까지' 를 범위가 아닌 열거로 추출.
"""
from __future__ import annotations

from app.core.product_extract import extract_products
from app.core.versioning import version_matches


# ── D1: 굵은 상한 경계가 자기 계열을 포함해야 한다 ──────────────────────────────

def test_coarse_lte_includes_its_own_branch():
    """'124 이하' 는 124.x 전체를 포함한다. 취약한 Chrome 124.0.6367.91 은 매칭(확정)."""
    rule = {"lte": "124"}
    assert version_matches("124.0.6367.91", rule) == (True, False)   # 예전: (False, False)
    assert version_matches("124.0", rule) == (True, False)
    assert version_matches("123.5", rule) == (True, False)
    assert version_matches("125.0", rule) == (False, False)          # 상위 계열은 미매칭(확정)


def test_coarse_lt_excludes_its_own_branch():
    """엄격 '124 미만' 은 124.x 를 제외한다(124 계열은 아직 '미만' 이 아님)."""
    rule = {"lt": "124"}
    assert version_matches("124.0.6367.91", rule) == (False, False)
    assert version_matches("123.9", rule) == (True, False)


def test_coarse_gte_includes_its_own_branch():
    """'124 이상' 은 124.x 를 포함한다."""
    rule = {"gte": "124"}
    assert version_matches("124.0.6367.91", rule) == (True, False)
    assert version_matches("123.9", rule) == (False, False)


def test_precise_boundary_stays_confident():
    """양쪽이 같은 정밀도면 종전처럼 확정 비교(후보 아님) — 정밀 NVD 경계 회귀 방지."""
    rule = {"lt": "124.0.6367.78"}
    assert version_matches("124.0.6367.50", rule) == (True, False)
    assert version_matches("124.0.6367.78", rule) == (False, False)
    assert version_matches("124.0.6367.91", rule) == (False, False)


def test_less_precise_asset_is_candidate_not_confident_miss():
    """자산이 규칙보다 덜 구체적이면(빌드번호 누락) 확신 미탐이 아니라 후보로 넘긴다."""
    # 예전 zero-padding 은 '10.0.19045' 를 '...0' 으로 채워 확정 판정했다.
    assert version_matches("10.0.19045", {"lt": "10.0.19045.4291"}) == (True, True)


# ── D2: 서로 다른 버전 체계는 확신 비교하지 않는다(후보로) ──────────────────────

def test_windows_feature_update_vs_build_rule_is_candidate():
    """Windows 기능 업데이트 라벨('22H2'→2022)과 빌드 규칙('10.0.19045.x')은 체계가 다르다.

    예전엔 (2022,2) > (10,...) 로 계산돼 취약 자산을 확신-미탐했다. 이제 후보(사람 검토).
    """
    assert version_matches("22H2", {"lt": "10.0.19045.4291"}) == (True, True)
    assert version_matches("23H2", {"lte": "10.0.22631.0"}) == (True, True)


def test_windows_server_year_vs_build_rule_is_candidate():
    """Windows Server 연도('2019')와 빌드 규칙도 체계 불일치 → 후보."""
    assert version_matches("2019", {"lt": "10.0.17763.5000"}) == (True, True)


def test_same_scheme_years_still_compare():
    """둘 다 연도형이면 정상 비교(오탐 후보 남발 방지) — 한컴/오피스 연도 회귀."""
    assert version_matches("2019", {"lte": "2021"}) == (True, False)
    assert version_matches("2022", {"lte": "2021"}) == (False, False)


def test_same_scheme_semver_still_compares():
    """둘 다 통상 semver 면 체계 오인 없이 정상 비교 — 후보 남발 회귀 방지."""
    assert version_matches("9.0.49", {"lt": "9.0.50"}) == (True, False)
    assert version_matches("9.0.50", {"lt": "9.0.50"}) == (False, False)


# ── D3: 'X 부터 Y 까지' 는 열거가 아니라 범위로 추출 ───────────────────────────

def test_korean_from_to_phrase_becomes_range():
    """가장 흔한 한국어 범위 표현을 범위 규칙으로 저장하고, 중간 버전이 매칭돼야 한다."""
    p = [x for x in extract_products("nginx 1.20.0 부터 1.24.0 까지 취약합니다.")
         if x["product_key"] == "nginx"][0]
    assert p["affected_versions"] == {"range": ["1.20.0", "1.24.0"]}
    assert version_matches("1.22.0", p["affected_versions"]) == (True, False)   # 예전: 미탐
    assert version_matches("1.19.0", p["affected_versions"]) == (False, False)
    assert version_matches("1.30.0", p["affected_versions"]) == (False, False)


def test_tilde_range_still_works():
    """물결형 범위는 종전대로 동작(회귀 방지)."""
    p = [x for x in extract_products("nginx 1.20.0 ~ 1.24.0 취약합니다.")
         if x["product_key"] == "nginx"][0]
    assert p["affected_versions"] == {"range": ["1.20.0", "1.24.0"]}


def test_bare_from_phrase_is_gte_not_range():
    """상한('까지') 없는 단독 'X 부터' 는 상한 미상이므로 '이상(gte)' 으로 해석한다."""
    p = [x for x in extract_products("nginx 1.20.0 부터 영향을 받습니다.")
         if x["product_key"] == "nginx"][0]
    assert p["affected_versions"] == {"gte": "1.20.0"}
    assert version_matches("1.25.0", p["affected_versions"]) == (True, False)
    assert version_matches("1.19.0", p["affected_versions"]) == (False, False)


# ── D4: 한 제품에 영향 범위가 여럿인 표(any 규칙) ──────────────────────────────
#
# 권고문 표는 같은 제품에 범위를 여러 줄로 적는다:
#   | CVE-2026-8461 | FFmpeg | 8.1.0 이상 8.1.2 미만 | 8.1.2 |
#   | CVE-2026-8461 | FFmpeg | 8.0.0 이상 8.0.3 미만 | 8.1.3 |
# AdvisoryProduct 는 (권고문, 제품키)당 1행이라 두 범위를 한 규칙에 담아야 하는데,
# 리스트로 담으면 '정확 버전 열거'로 해석돼 취약 자산이 조용히 누락된다. any 가 그 형식이다.

_FFMPEG = {"any": [{"gte": "8.1.0", "lt": "8.1.2", "fixed": "8.1.2"},
                   {"gte": "8.0.0", "lt": "8.0.3", "fixed": "8.1.3"}]}


def test_any_matches_each_branch():
    assert version_matches("8.1.1", _FFMPEG) == (True, False)   # 첫 범위
    assert version_matches("8.0.2", _FFMPEG) == (True, False)   # 둘째 범위


def test_any_excludes_versions_outside_every_branch():
    """어느 범위에도 안 들면 확정 미매칭 — 고친 버전을 취약으로 부르면 안 된다."""
    assert version_matches("8.1.2", _FFMPEG) == (False, False)  # 첫 범위 상한(미만)
    assert version_matches("8.0.3", _FFMPEG) == (False, False)  # 둘째 범위 상한
    assert version_matches("7.9.0", _FFMPEG) == (False, False)
    assert version_matches("9.0.0", _FFMPEG) == (False, False)


def test_any_prefers_confirmed_match_over_candidate():
    """확정 매칭이 있으면 다른 가지의 '비교 불가 후보' 가 그것을 가리면 안 된다."""
    rule = {"any": [{"lt": "알수없음"}, {"gte": "1.0", "lt": "2.0"}]}
    assert version_matches("1.5", rule) == (True, False)


def test_any_falls_back_to_candidate_when_no_branch_is_certain():
    """확정이 하나도 없고 비교 불가만 있으면 사람 검토 후보로 남긴다(조용히 버리지 않는다)."""
    rule = {"any": [{"lt": "알수없음"}, {"gte": "해석불가"}]}
    matched, candidate = version_matches("1.5", rule)
    assert (matched, candidate) == (True, True)


def test_any_with_unknown_asset_version_is_candidate():
    """자산 버전 미상은 기존 규칙과 동일하게 보수적 후보."""
    assert version_matches(None, _FFMPEG) == (True, True)
    assert version_matches("", _FFMPEG) == (True, True)


def test_malformed_any_is_conservative():
    """형태가 깨진 any 로 취약 자산이 조용히 사라지면 안 된다."""
    for bad in ({"any": []}, {"any": None}, {"any": "8.1.0"}):
        assert version_matches("8.1.1", bad) == (True, True), bad


def test_fixed_key_inside_subrule_is_ignored_by_matcher():
    """하위 규칙의 fixed 는 표시용 메타 — 비교에 영향을 주면 안 된다."""
    with_fixed = {"any": [{"gte": "8.1.0", "lt": "8.1.2", "fixed": "8.1.2"}]}
    without = {"any": [{"gte": "8.1.0", "lt": "8.1.2"}]}
    for v in ("8.1.0", "8.1.1", "8.1.2", "8.2.0"):
        assert version_matches(v, with_fixed) == version_matches(v, without), v


def test_existing_rule_forms_are_unaffected():
    """any 도입이 기존 형식의 의미를 바꾸지 않는다(하위 호환)."""
    assert version_matches("124.0", {"lte": "124"}) == (True, False)
    assert version_matches("22H2", ["22H2", "23H2"]) == (True, False)
    assert version_matches("DC2021", {"range": ["DC2019", "DC2023"]}) == (True, False)
    assert version_matches("1.0", "*") == (True, False)
