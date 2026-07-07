"""PDF 텍스트 추출 + CVE 코드 추출 (명세서 §4.1).

전략: 정규식(결정적·고속)으로 CVE 식별자를 추출한다. 표준형 외에 띄어쓰기·구분자
변형('CVE 2026 21345', 'CVE_2026_21345')도 정규화해 함께 잡는다.
"""
from __future__ import annotations

import hashlib
import re
from datetime import date

# 표준형(하이픈) 및 변형(공백/언더스코어 구분자, PDF 표 추출 시 다중 공백) 모두 수용.
# group(1)=연도, group(2)=일련번호 → 'CVE-YYYY-NNNN' 표준형으로 정규화.
CVE_RE = re.compile(r"CVE[\s\-_]*(\d{4})[\s\-_]+(\d{4,7})", re.IGNORECASE)

# ── 조치기한 추출(§8) — 한글 권고문 표기 변형 수용. 본문에 없으면 None(관리자 수동 입력). ──
# 날짜: 2026.6.26 / 2026-06-26 / 2026년 6월 26일 / 2026/6/26.
_DATE_RE = r"(\d{4})\s*[.\-/년]\s*(\d{1,2})\s*[.\-/월]\s*(\d{1,2})"
# '조치/완료/이행/시정 (완료) 기한 … 날짜' 또는 '날짜 (일) 까지/이내'.
_DUE_KEYWORD_RE = re.compile(r"(?:조치|완료|이행|시정)\s*(?:완료\s*)?기한[^\d]{0,25}" + _DATE_RE)
_DUE_UNTIL_RE = re.compile(_DATE_RE + r"\s*일?\s*(?:까지|이내)")

# ── 접수경로 추출(§9) — 명시적 '접수/수신 경로' 라벨이 있을 때만. 라벨 없으면 None(관리자 입력). ──
_CHANNEL_LABEL_RE = re.compile(r"(?:접수|수신)\s*경로\s*[:：]?\s*([^\n,。·]{1,40})")
_CHANNEL_RULES = [
    ("NCST", re.compile(r"국가\s*사이버안보센터|사이버안보센터|NCSC|NCST|전용망|국가정보원|국정원")),
    ("OFFICIAL_DOC", re.compile(r"공문|시행문|문서번호|발신\s*명의")),
    ("WEBMAIL", re.compile(r"웹\s*메일|전자우편|이메일|e-?mail", re.IGNORECASE)),
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def extract_text_from_pdf(path: str) -> tuple[str, int]:
    """텍스트 PDF에서 본문 추출. 반환 (text, page_count).

    스캔본(이미지) PDF의 OCR은 본 구현 범위 밖(§4.1 주석) — 빈 텍스트가 나오면
    호출측이 사용자에게 수동 입력/OCR을 안내한다.
    """
    try:
        from pypdf import PdfReader
    except Exception:
        return "", 0
    try:
        reader = PdfReader(path)
        pages = reader.pages
        parts = []
        for p in pages:
            try:
                parts.append(p.extract_text() or "")
            except Exception:
                parts.append("")
        return "\n".join(parts), len(pages)
    except Exception:
        return "", 0


def _regex_candidates(text: str) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for m in CVE_RE.finditer(text or ""):
        code = f"CVE-{m.group(1)}-{m.group(2)}"
        if code in seen:
            continue
        seen.add(code)
        start = max(0, m.start() - 50)
        end = min(len(text), m.end() + 50)
        snippet = re.sub(r"\s+", " ", text[start:end]).strip()
        out.append({"cve_id_text": code, "source_snippet": snippet, "confidence": 1.0})
    return out


def extract_cve_codes(text: str) -> list[dict]:
    """본문에서 CVE 코드 목록 추출(정규식). 중복 제거, 순서 보존."""
    return _regex_candidates(text)


def extract_due_date(text: str) -> tuple[date | None, str | None]:
    """본문에서 조치기한 추출(best-effort). 반환 (기한 date|None, 근거 스니펫|None).

    '조치기한' 등 키워드 뒤 날짜를 우선, 없으면 '날짜 …까지/이내' 패턴. 둘 다 없으면 None
    → 호출측이 관리자 수동 입력으로 처리(§8). 취약점 조치가이드형 PDF엔 보통 기한이 없음.
    """
    t = text or ""
    for rx in (_DUE_KEYWORD_RE, _DUE_UNTIL_RE):
        m = rx.search(t)
        if not m:
            continue
        try:
            due = date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            continue
        start, end = max(0, m.start() - 18), min(len(t), m.end() + 8)
        return due, re.sub(r"\s+", " ", t[start:end]).strip()
    return None, None


def extract_receive_channel(text: str) -> tuple[str | None, str | None]:
    """본문에서 접수경로 추출(best-effort). 반환 (ReceiveChannel 값|None, 근거 스니펫|None).

    명시적 '접수경로/수신경로' 라벨이 있을 때만 분류한다(라벨 없이 본문 키워드로 추정하면
    오탐 위험). 라벨이 없으면 None → 관리자 수동 입력(§9).
    """
    t = text or ""
    m = _CHANNEL_LABEL_RE.search(t)
    if not m:
        return None, None
    snippet = re.sub(r"\s+", " ", m.group(0)).strip()
    value = m.group(1)
    for code, rx in _CHANNEL_RULES:
        if rx.search(value):
            return code, snippet
    return None, snippet  # 라벨은 있으나 분류 불가 → 채널 None, 스니펫만(관리자 확인)
