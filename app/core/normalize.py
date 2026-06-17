"""제품 정규화 (명세서 §4.6-1).

자산대장의 원문 제품/OS 문자열과 CVE 피드의 제품명을 동일한 `product_key`로 변환한다.
별칭 사전은 운영 중 추가 가능하도록 모듈 상수로 관리하며, DB 설정 테이블로 옮길 수 있다.
"""
from __future__ import annotations

import re

# canonical product_key -> 별칭(소문자 부분일치) 목록
PRODUCT_ALIASES: dict[str, list[str]] = {
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

# 별칭 → key 역인덱스 (긴 별칭 우선 매칭).
_ALIAS_INDEX: list[tuple[str, str]] = sorted(
    ((alias, key) for key, aliases in PRODUCT_ALIASES.items() for alias in aliases),
    key=lambda t: len(t[0]),
    reverse=True,
)


def normalize_product(raw: str | None) -> str:
    """원문 제품 문자열 → product_key. 미상은 슬러그화한 폴백 키를 반환."""
    if not raw:
        return ""
    text = raw.strip().lower()
    for alias, key in _ALIAS_INDEX:
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
    for alias, _key in _ALIAS_INDEX:  # 길이 내림차순 → 첫 매칭이 최장
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
    """운영 중 별칭 추가(메모리). DB 영속화는 설정 테이블로 확장."""
    alias = alias.strip().lower()
    PRODUCT_ALIASES.setdefault(product_key, [])
    if alias not in PRODUCT_ALIASES[product_key]:
        PRODUCT_ALIASES[product_key].append(alias)
        _ALIAS_INDEX.append((alias, product_key))
        _ALIAS_INDEX.sort(key=lambda t: len(t[0]), reverse=True)
