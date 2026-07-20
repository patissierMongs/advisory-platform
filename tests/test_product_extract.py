"""§개편 — 추출 엔진: 제품·영향버전 추출과 정규화 경계 매칭 단위 테스트."""
from __future__ import annotations

from app.core.normalize import normalize_product, split_product_version
from app.core.product_extract import extract_products
from app.core.versioning import version_matches


def _one(text: str, key: str) -> dict:
    hits = [p for p in extract_products(text) if p["product_key"] == key]
    assert hits, f"{key} not extracted from: {text}"
    return hits[0]


# ── 정규화: Apache vs Apache Storm ────────────────────────────────────────────

def test_apache_storm_is_not_apache_httpd():
    assert normalize_product("Apache Storm") == "apache_storm"
    assert normalize_product("Apache Tomcat") == "apache_tomcat"
    assert normalize_product("Apache") == "apache_httpd"
    assert normalize_product("Apache HTTP Server 2.4") == "apache_httpd"


def test_unknown_apache_subproduct_falls_back_to_slug():
    # 사전에 없는 하위 제품이 httpd 로 오인되면 안 된다.
    assert normalize_product("Apache Druid") == "apache_druid"


def test_alias_requires_word_boundary():
    assert normalize_product("aiis server") != "microsoft_iis"
    assert normalize_product("IIS 10.0") == "microsoft_iis"


def test_split_product_version_still_works():
    assert split_product_version("Windows 11 22H2") == ("Windows 11", "22H2")
    assert split_product_version("Apache Tomcat 9.0.30")[1] == "9.0.30"


# ── 버전 범위 구문 해석 ───────────────────────────────────────────────────────

def test_lte_phrase_becomes_range_rule():
    p = _one("Apache HTTP Server 2.4.57 이하 버전에서 취약점 발견", "apache_httpd")
    assert p["affected_versions"] == {"lte": "2.4.57"}
    # "이하" 규칙이면 그 아래 버전 전부가 매칭되어야 한다.
    assert version_matches("2.2.1", p["affected_versions"]) == (True, False)
    assert version_matches("2.4.57", p["affected_versions"]) == (True, False)
    assert version_matches("2.4.58", p["affected_versions"]) == (False, False)


def test_fix_version_is_not_affected_version():
    # "9.0.50 이상으로 업데이트" — 9.0.50 은 조치 버전. 영향은 {"lt": 9.0.50} 로 유도.
    p = _one("Apache Tomcat 취약점. 9.0.50 이상으로 업데이트 하시기 바랍니다.", "apache_tomcat")
    assert p["fixed_version"] == "9.0.50"
    assert p["affected_versions"] == {"lt": "9.0.50"}
    assert version_matches("9.0.50", p["affected_versions"]) == (False, False)
    assert version_matches("9.0.49", p["affected_versions"]) == (True, False)


def test_tilde_range_and_separate_fix():
    p = _one("Chrome 120 ~ 123 버전이 영향을 받으며 124 이상으로 업데이트 필요.", "google_chrome")
    assert p["affected_versions"] == {"range": ["120", "123"]}
    assert p["fixed_version"] == "124"


def test_multi_product_single_advisory():
    text = ("본 취약점은 HTTP 스택 전반에 영향. Apache 2.4.58 이하, nginx 1.24.0 미만, "
            "Microsoft IIS 10.0, Apache Tomcat 8.5 ~ 9.0.30 버전이 영향을 받음.")
    keys = {p["product_key"]: p for p in extract_products(text)}
    assert keys["apache_httpd"]["affected_versions"] == {"lte": "2.4.58"}
    assert keys["nginx"]["affected_versions"] == {"lt": "1.24.0"}
    assert keys["apache_tomcat"]["affected_versions"] == {"range": ["8.5", "9.0.30"]}
    assert "microsoft_iis" in keys


def test_numbers_in_dates_docno_cve_are_not_versions():
    text = "제2026-123호 (2026. 6. 12.) CVE-2026-21345 관련 안내. 총 3건, 조치율 80% 달성 요망."
    assert extract_products(text) == []


def test_common_word_alias_needs_version_evidence():
    # '한글'은 일반 명사 — 버전 문맥 없이 제품으로 올리면 안 된다.
    assert extract_products("본 문서는 한글 문서로 작성되었습니다.") == []
    p = _one("한컴오피스 2020 및 이전 버전에서 취약점 발견.", "hancom_office")
    assert p["affected_versions"] == {"lte": "2020"}


def test_unknown_product_suggested_with_range_phrase():
    p = _one("GitLab CE 16.11.1 이하 버전에서 계정 탈취 취약점이 확인됨.", "gitlab_ce")
    assert p["affected_versions"] == {"lte": "16.11.1"}
    assert p["confidence"] <= 0.5


# ── 다중 연산 규칙 평가(versioning 확장) ─────────────────────────────────────

def test_version_matches_multi_op_dict():
    rule = {"gte": "8.5", "lt": "9.0.30"}
    assert version_matches("8.5", rule) == (True, False)
    assert version_matches("9.0.29", rule) == (True, False)
    assert version_matches("9.0.30", rule) == (False, False)
    assert version_matches("8.4", rule) == (False, False)
