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
