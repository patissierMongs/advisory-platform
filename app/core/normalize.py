"""제품 정규화 (명세서 §4.6-1).

자산대장의 원문 제품/OS 문자열과 CVE 피드의 제품명을 동일한 `product_key`로 변환한다.
별칭 사전은 운영 중 추가 가능하도록 모듈 상수로 관리하며, DB 설정 테이블로 옮길 수 있다.

매칭 규칙(§개편 — 오인 매칭 방지):
  1) 토큰 경계 매칭 — 별칭은 단어 경계에서만 일치한다("iis"가 "aiis" 내부에 걸리지 않음).
  2) 최장 일치 우선 — "apache tomcat" 이 "apache" 보다 먼저 매칭된다.
  3) 벤더 접두어 가드 — "apache"·"microsoft" 같은 벤더명 단독 별칭은 바로 뒤에
     다른 제품 단어가 이어지면(예: "Apache Storm") 매칭하지 않는다. 사전에 없는
     하위 제품은 슬러그 키(apache_storm)로 남아 Apache HTTPD 와 절대 섞이지 않는다.
"""
from __future__ import annotations

import re

# canonical product_key -> 별칭(소문자, 토큰 경계 일치) 목록
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
    "apache_httpd": ["apache httpd", "apache http server", "apache http", "httpd", "apache"],
    "apache_tomcat": ["apache tomcat", "tomcat", "톰캣"],
    "apache_storm": ["apache storm"],
    "apache_kafka": ["apache kafka", "kafka"],
    "apache_struts": ["apache struts", "struts"],
    "apache_log4j": ["apache log4j", "log4j"],
    "nginx": ["nginx", "엔진엑스"],
    "microsoft_iis": ["microsoft iis", "internet information services", "iis"],
    "vmware_esxi": ["vmware esxi", "esxi"],
    "mysql": ["mysql"],
    "mariadb": ["mariadb"],
    "postgresql": ["postgresql", "postgres"],
    "oracle_database": ["oracle database", "oracle db"],
    "openjdk": ["openjdk"],
    "mozilla_firefox": ["mozilla firefox", "firefox", "파이어폭스"],
}

# 벤더명 단독 별칭 — 뒤에 다른 제품 단어가 이어지면 해당 별칭으로 매칭하지 않는다.
# (예: "Apache Storm" 에서 "apache" 별칭이 Apache HTTPD 로 오인되는 것 방지)
VENDOR_PREFIX_ALIASES: frozenset[str] = frozenset({"apache", "microsoft", "adobe", "oracle", "mozilla"})

# 버전형 토큰 — 별칭 뒤에 와도 '다른 제품 단어'로 보지 않는 것들.
_VERSIONISH = re.compile(r"^(?:v?\d|dc\b|\d{2}h\d|x\b|버전|version|server\b)", re.IGNORECASE)
# 벤더 가드는 라틴 단어만 '다른 제품명 후보'로 본다 — 한국어 후속어(웹서버·취약점·서버 등)는
# 제품명이 아니라 일반 명사이므로 거부하면 "Apache 웹서버 취약점"에서 제품을 놓친다(§스트레스 S02).
_NEXT_WORD = re.compile(r"^[\s\-_/·]*([A-Za-z][A-Za-z0-9]*)")


def _boundary_ok(text: str, start: int, end: int) -> bool:
    """별칭 일치 구간이 단어 경계 위에 있는지(앞뒤가 영숫자/한글이 아닌지)."""
    if start > 0 and re.match(r"[a-z0-9가-힣]", text[start - 1], re.IGNORECASE):
        return False
    if end < len(text) and re.match(r"[a-z0-9가-힣]", text[end], re.IGNORECASE):
        return False
    return True


def _vendor_guard_ok(alias: str, text: str, end: int) -> bool:
    """벤더 단독 별칭('apache' 등)은 뒤에 다른 제품 단어가 이어지면 매칭 거부."""
    if alias not in VENDOR_PREFIX_ALIASES:
        return True
    rest = text[end:]
    m = _NEXT_WORD.match(rest)
    if not m:
        return True                        # 문자열 끝/구두점 → "Apache 2.4" · "Apache" 단독
    word = m.group(1)
    return bool(_VERSIONISH.match(word))   # 버전형이면 허용, 제품 단어면 거부


def _find_alias(text: str) -> tuple[str, str, int, int] | None:
    """text(소문자)에서 규칙을 만족하는 최장 별칭 검색. 반환 (alias, key, start, end)."""
    for alias, key in _ALIAS_INDEX:
        i = text.find(alias)
        while i != -1:
            end = i + len(alias)
            if _boundary_ok(text, i, end) and _vendor_guard_ok(alias, text, end):
                return alias, key, i, end
            i = text.find(alias, i + 1)
    return None


def slugify(text: str) -> str:
    """영숫자/한글만 남긴 슬러그 키(사전 미등록 제품도 키 일관성 유지)."""
    return re.sub(r"[^a-z0-9가-힣]+", "_", text.strip().lower()).strip("_")


def normalize_product(raw: str | None) -> str:
    """원문 제품 문자열 → product_key. 미상은 슬러그화한 폴백 키를 반환."""
    if not raw:
        return ""
    text = raw.strip().lower()
    hit = _find_alias(text)
    if hit:
        return hit[1]
    return slugify(text) or ""


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
    hit = _find_alias(low)
    if hit:
        _alias, _key, i, end = hit
        product = text[:end].strip()
        version = text[end:].strip(" -/().,")
        return (product or text), version
    tokens = text.split()
    for ti, tok in enumerate(tokens):
        if _VER_TOKEN.match(tok):
            return (" ".join(tokens[:ti]).strip() or text), " ".join(tokens[ti:]).strip()
    return text, ""


def _build_index() -> list[tuple[str, str]]:
    return sorted(
        ((alias, key) for key, aliases in PRODUCT_ALIASES.items() for alias in aliases),
        key=lambda t: len(t[0]),
        reverse=True,
    )


# 별칭 → key 역인덱스 (긴 별칭 우선 매칭).
_ALIAS_INDEX: list[tuple[str, str]] = _build_index()


def register_alias(product_key: str, alias: str) -> None:
    """운영 중 별칭 추가(메모리). DB 영속화는 설정 테이블로 확장."""
    global _ALIAS_INDEX
    alias = alias.strip().lower()
    PRODUCT_ALIASES.setdefault(product_key, [])
    if alias not in PRODUCT_ALIASES[product_key]:
        PRODUCT_ALIASES[product_key].append(alias)
        _ALIAS_INDEX = _build_index()


def _alias_ok(alias: str) -> bool:
    """사전에 넣을 만한 별칭인가 — 잡음(빈값·기호·과도하게 짧은 것) 배제.

    라틴 별칭은 3자 미만이면 잡음(약어 오인)일 확률이 높아 배제하되,
    한글 제품명은 2음절이 흔하므로('알약' 등) 2자부터 허용한다.
    """
    if not alias or len(alias) < 2:
        return False
    if len(alias) < 3 and not re.search(r"[가-힣]", alias):
        return False
    if not re.search(r"[a-z가-힣]", alias):
        return False               # 숫자·기호뿐인 이름 배제
    return alias not in ("n/a", "none", "unknown", "기타")


def sync_aliases_from_cves(pairs) -> int:
    """CVE DB 의 (product_name, product_key) 목록을 추출 사전에 반영(§개편 후속).

    피드 적용·기동 시 호출 — 피드로 들어온 실제 제품명이 본문 추출기의 인식 대상이 된다.
    벌크로 모아 인덱스는 1회만 재구축. 반환: 신규 등록 별칭 수.
    """
    global _ALIAS_INDEX
    existing = {a for a, _k in _ALIAS_INDEX}
    n = 0
    for name, key in pairs:
        if not name or not key:
            continue
        alias = str(name).strip().lower()
        if not _alias_ok(alias) or alias in existing:
            continue
        # 충돌 가드: 다른 키의 더 긴 기존 별칭에 부분 포함되는 짧은 이름('server' 류)은
        # 자산·본문 정규화를 엉뚱한 키로 끌고 갈 수 있어 배제(같은 키면 무해하므로 허용).
        if len(alias) <= 12 and any(
            alias != a2 and alias in a2 and k2 != key for a2, k2 in _ALIAS_INDEX
        ):
            continue
        PRODUCT_ALIASES.setdefault(key, []).append(alias)
        existing.add(alias)
        n += 1
    if n:
        _ALIAS_INDEX = _build_index()
    return n
