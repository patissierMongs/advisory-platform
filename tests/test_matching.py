"""매칭 판정 — version_norm/version_raw 이중 판정(관리자↔서버 매칭 일치) 테스트."""
from __future__ import annotations

from app.core.matching import asset_matches_cve
from app.models import Asset, Cve


def _asset(**kw):
    base = dict(asset_no="PDF-090", department_id=1, product_key="adobe_acrobat_dc",
                version_norm="21.001.20155", version_raw="2021")
    base.update(kw)
    return Asset(**base)


def test_version_raw_fallback_matches():
    """정규화 버전은 목록에 없지만 원본('2021')이 영향버전 목록에 있으면 매칭(확정)."""
    cve = Cve(product_key="adobe_acrobat_dc", affected_versions=["2021"])
    ok, reason = asset_matches_cve(_asset(), cve)
    assert ok is True
    assert reason["candidate"] is False           # 원본으로 확정 일치
    assert reason["asset_version_raw"] == "2021"


def test_no_match_when_neither_version_satisfies():
    """norm·raw 모두 규칙 불만족이면 비매칭."""
    cve = Cve(product_key="adobe_acrobat_dc", affected_versions=["2019"])
    ok, reason = asset_matches_cve(_asset(), cve)
    assert ok is False and reason is None


def test_product_key_mismatch_never_matches():
    cve = Cve(product_key="windows", affected_versions="*")
    assert asset_matches_cve(_asset(), cve) == (False, None)


def test_missing_version_is_candidate():
    """버전 한정 규칙 + 자산 버전 미상 → 보수적 후보로 매칭(누락 방지)."""
    cve = Cve(product_key="adobe_acrobat_dc", affected_versions=["2021"])
    ok, reason = asset_matches_cve(_asset(version_norm=None, version_raw=None), cve)
    assert ok is True and reason["candidate"] is True
