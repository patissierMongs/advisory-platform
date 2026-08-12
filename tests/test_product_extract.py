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


# ── 스트레스 라운드 회귀(§스트레스 S02·S05) ──────────────────────────────────

def test_vendor_guard_allows_korean_following_word():
    # "Apache 웹서버/취약점" — 한국어 후속어는 하위 제품명이 아니므로 httpd 로 인식해야 한다.
    p = _one("Apache 웹서버 취약점 주의. 2.4.57 이하 버전이 영향받음.", "apache_httpd")
    assert p["affected_versions"] == {"lte": "2.4.57"}
    assert normalize_product("Apache 웹서버") == "apache_httpd"
    # 라틴 하위 제품명은 여전히 가드된다.
    assert normalize_product("Apache Druid") == "apache_druid"


def test_hversion_not_truncated_and_month_not_version():
    # 22H2 가 22 로 잘리거나 "6월"의 6 이 버전으로 들어가면 안 된다.
    p = _one("Windows 11 2026년 6월 정기 업데이트 권고. 22H2, 23H2 버전 영향.", "windows_11")
    assert p["affected_versions"] == ["22H2", "23H2"]


# ── 다중 연산 규칙 평가(versioning 확장) ─────────────────────────────────────

def test_version_matches_multi_op_dict():
    rule = {"gte": "8.5", "lt": "9.0.30"}
    assert version_matches("8.5", rule) == (True, False)
    assert version_matches("9.0.29", rule) == (True, False)
    assert version_matches("9.0.30", rule) == (False, False)
    assert version_matches("8.4", rule) == (False, False)


# ── 표 셀에서 추출 (§표 기반 추출) ─────────────────────────────────────────────
#
# 권고문의 주 서식은 표다. 열 의미가 명시적이라 본문 스캔보다 정확해야 한다.

import pytest  # noqa: E402
from app.core.pdf_tables import TableRow  # noqa: E402
from app.core.product_extract import _scan_window, extract_products_from_table  # noqa: E402
from app.core.versioning import version_matches  # noqa: E402


def _by_key(items):
    return {p["product_key"]: p for p in items}


def test_table_row_yields_bounded_range():
    rows = [TableRow(cve="CVE-2026-8461", product="FFmpeg",
                     affected="8.1.0 이상 8.1.2 미만", fixed="8.1.2")]
    p = _by_key(extract_products_from_table(rows))["ffmpeg"]
    assert p["product_name"] == "FFmpeg"
    assert p["affected_versions"]["gte"] == "8.1.0"
    assert p["affected_versions"]["lt"] == "8.1.2"
    assert p["fixed_version"] == "8.1.2"


def test_same_product_multiple_ranges_merge_into_any():
    """사용자 예시 그대로 — 제품당 1행 제약 안에서 두 범위가 모두 살아남아야 한다."""
    rows = [TableRow(cve="CVE-2026-8461", product="FFmpeg",
                     affected="8.1.0 이상 8.1.2 미만", fixed="8.1.2"),
            TableRow(cve="CVE-2026-8461", product="FFmpeg",
                     affected="8.0.0 이상 8.0.3 미만", fixed="8.1.3")]
    p = _by_key(extract_products_from_table(rows))["ffmpeg"]
    rule = p["affected_versions"]
    assert "any" in rule and len(rule["any"]) == 2, rule
    assert p["fixed_version"] == "8.1.2, 8.1.3"

    # 실제 매칭까지 확인 — 두 범위 모두 취약으로, 해결 버전은 안전으로 판정돼야 한다.
    assert version_matches("8.1.1", rule) == (True, False)
    assert version_matches("8.0.2", rule) == (True, False)
    assert version_matches("8.1.2", rule) == (False, False)
    assert version_matches("8.0.3", rule) == (False, False)


def test_per_range_fixed_version_is_carried_but_ignored_by_matcher():
    rows = [TableRow(product="FFmpeg", affected="8.1.0 이상 8.1.2 미만", fixed="8.1.2"),
            TableRow(product="FFmpeg", affected="8.0.0 이상 8.0.3 미만", fixed="8.1.3")]
    rule = _by_key(extract_products_from_table(rows))["ffmpeg"]["affected_versions"]
    assert [s["fixed"] for s in rule["any"]] == ["8.1.2", "8.1.3"]
    # fixed 키가 비교에 끼어들지 않는지 — 없는 규칙과 결과가 같아야 한다.
    bare = {"any": [{k: v for k, v in s.items() if k != "fixed"} for s in rule["any"]]}
    for v in ("8.0.2", "8.1.1", "8.1.2", "9.0.0"):
        assert version_matches(v, rule) == version_matches(v, bare), v


@pytest.mark.parametrize(("affected", "expected"), [
    ("9.0.90 미만", {"lt": "9.0.90"}),
    ("124 이하", {"lte": "124"}),
    ("10.1.25 이상", {"gte": "10.1.25"}),
    ("3.0.0 ~ 3.0.14", {"range": ["3.0.0", "3.0.14"]}),
    ("3.0.0 부터 3.0.14 까지", {"range": ["3.0.0", "3.0.14"]}),
])
def test_single_bound_and_range_forms(affected, expected):
    rows = [TableRow(product="OpenSSL", affected=affected)]
    rule = _by_key(extract_products_from_table(rows))["openssl"]["affected_versions"]
    assert {k: v for k, v in rule.items() if k != "fixed"} == expected


def test_enumerated_versions_stay_a_list():
    rows = [TableRow(product="Windows 11", affected="22H2, 23H2", fixed="")]
    rule = _by_key(extract_products_from_table(rows))["windows_11"]["affected_versions"]
    assert rule == ["22H2", "23H2"]


def test_unparseable_version_text_is_kept_not_dropped():
    """'특정 버전으로 마이그레이션' 같은 문구를 버리면 관리자가 대상 없음으로 오해한다."""
    rows = [TableRow(cve="CVE-2026-5555", product="LegacyApp",
                     affected="특정 버전으로 마이그레이션 필요", fixed="")]
    p = _by_key(extract_products_from_table(rows))["legacyapp"]
    assert p["affected_versions"] == "*"
    assert "마이그레이션" in p["source_snippet"], "원문이 남아야 관리자가 보정할 수 있다"


def test_unknown_rule_dominates_merge():
    """해석 불가가 섞이면 좁은 범위로 줄이면 안 된다 — 상위집합('*')을 택한다."""
    rows = [TableRow(product="LegacyApp", affected="1.0 이상 2.0 미만"),
            TableRow(product="LegacyApp", affected="문자열 버전")]
    rule = _by_key(extract_products_from_table(rows))["legacyapp"]["affected_versions"]
    assert rule == "*"


def test_product_alias_is_normalised_to_canonical_key():
    rows = [TableRow(product="Microsoft Windows 11", affected="22H2")]
    items = _by_key(extract_products_from_table(rows))
    assert "windows_11" in items, list(items)


def test_unknown_product_falls_back_to_slug():
    """사전에 없는 제품도 표에 적혀 있으면 살린다."""
    rows = [TableRow(product="SomeNewTool", affected="1.0 미만", fixed="1.0")]
    items = _by_key(extract_products_from_table(rows))
    assert "somenewtool" in items, list(items)


def test_multiple_fixed_versions_are_preserved():
    rows = [TableRow(product="Apache Tomcat", affected="9.0.90 미만", fixed="9.0.90, 10.1.25")]
    p = _by_key(extract_products_from_table(rows))["apache_tomcat"]
    assert p["fixed_version"] == "9.0.90, 10.1.25"


def test_empty_or_blank_rows_are_skipped():
    rows = [TableRow(), TableRow(product="", affected="1.0 미만")]
    assert extract_products_from_table(rows) == []


def test_return_schema_matches_text_extraction():
    """하류(refresh_extracted_products)가 두 경로를 구분하지 않아야 한다."""
    table = extract_products_from_table([TableRow(product="OpenSSL", affected="3.0.0 미만")])[0]
    assert set(table) == {"product_name", "product_key", "affected_versions",
                          "fixed_version", "source_snippet", "confidence"}


# ── 다중 범위 셀·반쪽 범위·연락처 방어 (§실사용 결함 회귀) ─────────────────────

def test_two_ranges_stacked_in_one_cell_both_survive():
    """한 셀에 완결 범위가 줄바꿈으로 두 개 — 통째로 해석하면 마지막 범위만 남았다.
    (표 복원이 줄바꿈을 공백으로 잇기 때문에 셀 텍스트는 한 줄로 들어온다)"""
    rows = [TableRow(cve="CVE-2026-10712", product="GitLab EE",
                     affected="19.1 이상 19.1.1 미만 19.0 이상 19.0.3 미만", fixed="19.1.1")]
    p = _by_key(extract_products_from_table(rows))["gitlab_ee"]
    rule = p["affected_versions"]
    assert isinstance(rule, dict) and "any" in rule, rule
    subs = [{k: v for k, v in r.items() if k != "fixed"} for r in rule["any"]]
    assert {"gte": "19.1", "lt": "19.1.1"} in subs, rule
    assert {"gte": "19.0", "lt": "19.0.3"} in subs, rule


def test_split_half_ranges_across_rows_are_paired():
    """'19.1 이상'과 '19.1.1 미만'이 셀 안 줄바꿈으로 서로 다른 행이 된 경우 —
    반쪽 규칙 둘을 OR 로 합치면 사실상 전체 버전이 된다(확신-오답). 한 범위로 결합돼야 한다."""
    rows = [TableRow(cve="CVE-2026-1234", product="WebSphere Application Server",
                     affected="19.1 이상"),
            TableRow(cve="CVE-2026-1234", product="WebSphere Application Server",
                     affected="19.1.1 미만")]
    p = list(extract_products_from_table(rows))[0]
    rule = p["affected_versions"]
    assert isinstance(rule, dict) and "any" not in rule, rule
    assert rule.get("gte") == "19.1" and rule.get("lt") == "19.1.1", rule


def test_phone_number_is_not_extracted_as_versions():
    """실사용 확정 결함 — '담당자/연락처'의 전화번호 숫자 그룹이 버전 열거로 추출됐다.
    규칙은 '전체(*)'로 남아야 한다(스니펫에 원문 인용이 남는 것은 정상)."""
    text = "Apache Tomcat 취약점 관련 문의는 담당자 홍길동 (02-405-5118, 내선 5118) 에게 연락 바랍니다."
    items = _by_key(extract_products(text))
    for item in items.values():
        rule = item["affected_versions"]
        assert rule == "*", rule          # 전화번호가 버전 열거/범위로 잡히면 안 된다
        assert item["fixed_version"] is None


def test_standalone_year_version_survives_phone_guard():
    """전화번호 방어가 'Windows Server 2019' 류 단독 연도 버전을 죽이면 안 된다."""
    text = "Windows Server 2019 버전이 영향을 받습니다."
    items = _by_key(extract_products(text))
    assert items, "단독 연도 버전이 사라졌다"
    rule = next(iter(items.values()))["affected_versions"]
    assert "2019" in str(rule), rule


def test_fixed_cell_date_is_not_a_version():
    """해결버전 셀의 배포일("(2026.6.26 배포)")이 해결 버전으로 저장되던 결함."""
    rows = [TableRow(product="Apache Tomcat", affected="9.0.90 미만",
                     fixed="9.0.90 (2026.6.26 배포)")]
    p = _by_key(extract_products_from_table(rows))["apache_tomcat"]
    assert p["fixed_version"] == "9.0.90", p["fixed_version"]


def test_buteo_with_distant_kkaji_is_not_a_range():
    """'X 부터' 뒤 다른 문장의 '…까지'("붙임 문서까지")에 낚여 무관한 버전이
    상한이 되던 결함 — 상한 짝은 근처에서만 찾고, 못 찾으면 이상(gte)으로 남는다."""
    text = "1.0 부터 영향. 자세한 내용은 붙임 문서까지 확인하고 2.0 은 무관."
    rule = _scan_window(text, 0, len(text))["rule"]
    assert rule.get("gte") == "1.0", rule
    assert "range" not in rule, rule


def test_buteo_kkaji_nearby_is_still_a_range():
    rule = _scan_window("1.0 부터 2.0 까지", 0, 16)["rule"]
    assert rule == {"range": ["1.0", "2.0"]}, rule


def test_unparseable_affected_cell_lowers_confidence():
    """affected 셀이 있는데 해석 불가('해당 없음' → 전체*)면 고신뢰(0.95)로 표기되던
    결함 — 관리자가 '전체 버전 영향'을 확정 정보로 오해한다."""
    p = extract_products_from_table([TableRow(product="FooBar", affected="해당 없음")])[0]
    assert p["affected_versions"] == "*"
    assert p["confidence"] < 0.9, p["confidence"]
