"""PDF 텍스트 추출 + CVE 코드 추출 (명세서 §4.1–4.2).

전략: 1차 정규식(결정적·고속) → 2차 로컬 LLM 보완(선택, 폐쇄망 기본 비활성).
LLM 장애/비활성 시에도 정규식 결과로 진행 가능해야 한다(폴백).
"""
from __future__ import annotations

import hashlib
import re

from ..config import settings

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


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
        code = m.group(0).upper()
        if code in seen:
            continue
        seen.add(code)
        start = max(0, m.start() - 50)
        end = min(len(text), m.end() + 50)
        snippet = re.sub(r"\s+", " ", text[start:end]).strip()
        out.append({"cve_id_text": code, "source_snippet": snippet, "confidence": 1.0})
    return out


def _llm_augment(text: str) -> list[dict]:
    """로컬 LLM(Ollama) 보완 추출. 비활성/실패 시 빈 리스트(정규식 폴백)."""
    if not settings.LLM_ENABLED:
        return []
    from . import llm  # 지연 임포트

    codes = llm.extract_cves(text)
    if not codes:
        return []
    return [{"cve_id_text": c, "source_snippet": "(LLM 보완)", "confidence": 0.85} for c in codes]


def extract_cve_codes(text: str) -> list[dict]:
    """본문에서 CVE 코드 목록 추출(정규식 + 선택적 LLM). 중복 제거, 순서 보존."""
    results = _regex_candidates(text)
    seen = {r["cve_id_text"] for r in results}
    for extra in _llm_augment(text):
        if extra["cve_id_text"] not in seen:
            seen.add(extra["cve_id_text"])
            results.append(extra)
    return results
