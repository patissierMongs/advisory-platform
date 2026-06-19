"""PDF 텍스트 추출 + CVE 코드 추출 (명세서 §4.1).

전략: 정규식(결정적·고속)으로 CVE 식별자를 추출한다. 표준형 외에 띄어쓰기·구분자
변형('CVE 2026 21345', 'CVE_2026_21345')도 정규화해 함께 잡는다.
"""
from __future__ import annotations

import hashlib
import re

# 표준형(하이픈) 및 변형(공백/언더스코어 구분자, PDF 표 추출 시 다중 공백) 모두 수용.
# group(1)=연도, group(2)=일련번호 → 'CVE-YYYY-NNNN' 표준형으로 정규화.
CVE_RE = re.compile(r"CVE[\s\-_]*(\d{4})[\s\-_]+(\d{4,7})", re.IGNORECASE)


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
