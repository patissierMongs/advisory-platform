"""제품 정규화 (명세서 §4.6-1).

자산대장의 원문 제품/OS 문자열과 CVE 피드의 제품명을 동일한 `product_key`로 변환한다.
별칭 사전은 설정 파일(product_aliases — data/config/product_aliases.json)로 관리한다.
웹(설정 탭)에서 편집하거나 파일을 직접 수정하면 즉시 반영된다(§설정-파일 원칙).
"""
from __future__ import annotations

import re

from . import appconfig

# 설정 파일 로드 실패 시 폴백(부팅 안전) — 원본은 config/defaults/product_aliases.json.
_FALLBACK_ALIASES: dict[str, list[str]] = {
    "windows_11": ["windows 11", "win11", "win 11", "windows11", "window 11"],
    "windows_10": ["windows 10", "win10", "win 10", "windows10", "window 10"],
    "windows_server": ["windows server", "win server", "winsrv", "windows srv"],
    "microsoft_office": ["microsoft office", "ms office", "office", "msoffice", "오피스"],
    "google_chrome": ["google chrome", "chrome", "크롬"],
    "hancom_office": ["한컴오피스", "한컴 오피스", "hancom office", "hancom", "hwp", "한글"],
    "adobe_acrobat": [
        "adobe acrobat", "acrobat reader", "acrobat", "adobe reader", "어도비 아크로뱃",
    ],
    "edge": ["microsoft edge", "msedge", "edge", "엣지"],
    "linux_kernel": ["linux kernel", "리눅스 커널", "linux"],
    "ubuntu": ["ubuntu", "우분투"],
    "ibm_aix": ["aix"],
    "openssl": ["openssl"],
    "apache_httpd": ["apache httpd", "apache http server", "httpd", "apache"],
    "nginx": ["nginx"],
}

_INDEX_CACHE: tuple[int, list[tuple[str, str]]] | None = None  # (사전 해시, 역인덱스)


def _aliases() -> dict[str, list[str]]:
    try:
        cfg = appconfig.get_config("product_aliases")
        aliases = cfg.get("aliases")
        if isinstance(aliases, dict) and aliases:
            return aliases
    except Exception:  # noqa: BLE001 — 설정 파일 손상이 정규화 자체를 막지 않게
        pass
    return _FALLBACK_ALIASES


def _alias_index() -> list[tuple[str, str]]:
    """별칭 → key 역인덱스(긴 별칭 우선). 설정 내용이 바뀌면 재구축."""
    global _INDEX_CACHE
    aliases = _aliases()
    fingerprint = hash(tuple(sorted((k, tuple(v)) for k, v in aliases.items())))
    if _INDEX_CACHE and _INDEX_CACHE[0] == fingerprint:
        return _INDEX_CACHE[1]
    index = sorted(
        ((str(alias).lower(), key) for key, vals in aliases.items() for alias in vals),
        key=lambda t: len(t[0]),
        reverse=True,
    )
    _INDEX_CACHE = (fingerprint, index)
    return index


def normalize_product(raw: str | None) -> str:
    """원문 제품 문자열 → product_key. 미상은 슬러그화한 폴백 키를 반환."""
    if not raw:
        return ""
    text = raw.strip().lower()
    for alias, key in _alias_index():
        if alias in text:
            return key
    # 폴백: 영숫자/한글만 남겨 슬러그. (사전 미등록 제품도 키 일관성 유지)
    slug = re.sub(r"[^a-z0-9가-힣]+", "_", text).strip("_")
    return slug or ""


_VER_TOKEN = re.compile(r"^(?:\d|v\d|dc\b|\d{2}h\d)", re.IGNORECASE)


def split_product_version(raw: str | None) -> tuple[str, str]:
    """제품+버전이 한 셀에 섞인 경우 (제품, 버전)으로 분리.

    예: 'WINDOWS 11'→('WINDOWS 11','')  'WINDOW 10 H23'→('WINDOW 10','H23')
        'UBUNTU 22'→('UBUNTU','22')  'Chrome 122.x'→('Chrome','122.x')
    1) 알려진 제품 별칭이 포함되면 그 별칭 끝까지를 제품, 나머지를 버전으로
       (Windows 11/10 처럼 숫자가 제품명에 포함된 경우 보존).
    2) 별칭이 없으면 '숫자(또는 버전형)로 시작하는 첫 토큰'부터를 버전으로 본다.
    """
    if not raw:
        return "", ""
    text = str(raw).strip()
    low = text.lower()
    for alias, _key in _alias_index():  # 길이 내림차순 → 첫 매칭이 최장
        i = low.find(alias)
        if i != -1:
            product = text[: i + len(alias)].strip()
            version = text[i + len(alias):].strip(" -/().,")
            return (product or text), version
    tokens = text.split()
    for ti, tok in enumerate(tokens):
        if _VER_TOKEN.match(tok):
            return (" ".join(tokens[:ti]).strip() or text), " ".join(tokens[ti:]).strip()
    return text, ""


def register_alias(product_key: str, alias: str) -> None:
    """운영 중 별칭 추가 — 설정 파일(product_aliases)에 영속 저장, 즉시 반영."""
    alias = alias.strip().lower()
    if not alias:
        return
    aliases = {k: list(v) for k, v in _aliases().items()}
    aliases.setdefault(product_key, [])
    if alias not in aliases[product_key]:
        aliases[product_key].append(alias)
        appconfig.save_config("product_aliases", {"aliases": aliases})
