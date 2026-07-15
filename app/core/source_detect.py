"""출처(배포 기관) 자동 탐지 — 업로드된 권고문의 출처를 사람이 입력하지 않아도 지정.

탐지 우선순위(§요구): 상위 폴더명 → 폴더명 → 파일명 → 파일 내부(본문).
기관 목록·별칭은 설정 파일(source_orgs)로 관리 — 웹 편집·직접 수정 모두 즉시 반영.

여러 후보를 찾으면 전부(우선순위 순) 반환한다 — 화면에서 나열·클릭 선택(복수 가능),
최우선 후보가 자동 지정값이 된다. 하나도 없으면 호출측이 '-' 로 지정한다.
"""
from __future__ import annotations

import re

from . import appconfig

# 원문 스캔 상한 — 권고문 앞부분에 발신 기관이 나오므로 충분하고, 대형 PDF 도 안전.
_CONTENT_CAP = 30_000

ORIGIN_PARENT_FOLDER = "PARENT_FOLDER"
ORIGIN_FOLDER = "FOLDER"
ORIGIN_FILENAME = "FILENAME"
ORIGIN_CONTENT = "CONTENT"

ORIGIN_KO = {
    ORIGIN_PARENT_FOLDER: "상위 폴더명",
    ORIGIN_FOLDER: "폴더명",
    ORIGIN_FILENAME: "파일명",
    ORIGIN_CONTENT: "파일 내부",
    "MANUAL": "관리자 지정",
}


def _alias_regex(alias: str) -> re.Pattern:
    """짧은 영문 별칭(NIS 등)이 다른 단어 안에서 오탐하지 않게 — ASCII 는 경계 필수."""
    esc = re.escape(alias)
    if re.fullmatch(r"[A-Za-z0-9\-_. ]+", alias):
        return re.compile(r"(?<![A-Za-z0-9])" + esc + r"(?![A-Za-z0-9])", re.IGNORECASE)
    return re.compile(esc, re.IGNORECASE)


def _org_matchers() -> list[tuple[str, list[tuple[str, re.Pattern]]]]:
    cfg = appconfig.get_config("source_orgs")
    out: list[tuple[str, list[tuple[str, re.Pattern]]]] = []
    for org in cfg.get("organizations", []):
        name = str(org.get("name", "")).strip()
        if not name:
            continue
        aliases = [name] + [str(a).strip() for a in org.get("aliases", []) if str(a).strip()]
        out.append((name, [(a, _alias_regex(a)) for a in aliases]))
    return out


def _scan(s: str, matchers) -> list[tuple[int, str, str]]:
    """문자열 하나에서 기관 탐지 — (등장 위치, 기관명, 매칭 문자열) 을 위치순으로."""
    hits: list[tuple[int, str, str]] = []
    for name, patterns in matchers:
        best: tuple[int, str] | None = None
        for alias, rx in patterns:
            m = rx.search(s)
            if m and (best is None or m.start() < best[0]):
                best = (m.start(), m.group(0))
        if best:
            hits.append((best[0], name, best[1]))
    hits.sort(key=lambda h: h[0])
    return hits


def detect_sources(rel_path: str | None, filename: str | None, text: str | None) -> list[dict]:
    """출처 후보 목록 — 우선순위(상위 폴더명→폴더명→파일명→본문)·등장 순서 정렬, 기관명 중복 제거.

    반환: [{"name": 기관명, "origin": PARENT_FOLDER|FOLDER|FILENAME|CONTENT, "matched": 매칭 문자열}]
    """
    matchers = _org_matchers()
    if not matchers:
        return []

    # 경로 분해: "국가정보원/2026/권고.pdf" → 상위 폴더 ["국가정보원"], 폴더 "2026"
    segments = [s for s in re.split(r"[\\/]+", (rel_path or "").strip()) if s]
    if segments and filename and segments[-1] == filename:
        segments = segments[:-1]
    parent_segments = segments[:-1]          # 상위 폴더들(최상위부터)
    folder = segments[-1] if segments else ""  # 직속 폴더

    stem = (filename or "").rsplit(".", 1)[0]

    scans: list[tuple[str, str]] = []
    for seg in parent_segments:
        scans.append((ORIGIN_PARENT_FOLDER, seg))
    if folder:
        scans.append((ORIGIN_FOLDER, folder))
    if stem:
        scans.append((ORIGIN_FILENAME, stem))
    if text and text.strip():
        scans.append((ORIGIN_CONTENT, text[:_CONTENT_CAP]))

    seen: set[str] = set()
    out: list[dict] = []
    for origin, s in scans:
        for _pos, name, matched in _scan(s, matchers):
            if name in seen:
                continue
            seen.add(name)
            out.append({"name": name, "origin": origin, "matched": matched})
    return out
