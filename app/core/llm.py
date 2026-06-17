"""Ollama 기반 로컬 LLM — CVE 코드 추출 보완 (명세서 §4.2).

설계 원칙
  · 포터블: 외부 라이브러리 의존 0(stdlib urllib). 로컬·중앙 Ollama 모두 지원(URL 교체).
  · 안전: Ollama 부재·타임아웃·파싱 실패 시 None 반환 → 호출측이 정규식 결과로 진행(폴백).
  · 결정적: temperature=0 + format=json 으로 재현 가능한 JSON 추출.

LLM 은 '보완'이다 — 깨끗한 CVE 코드는 정규식이 처리하고, LLM 은 오타/표 깨짐/
'별도 통보'처럼 정규식이 놓치는 케이스를 메운다.
"""
from __future__ import annotations

import json
import re
import urllib.request

from ..config import settings

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_PROMPT = (
    "당신은 보안권고문에서 CVE 식별자만 추출하는 도구입니다.\n"
    "아래 문서에 실제로 등장하는 모든 CVE 코드를 찾으세요. "
    "'CVE 2026 21345' 같은 띄어쓰기·오타 변형은 표준형 'CVE-YYYY-NNNN'으로 교정하세요. "
    "문서에 없는 코드를 추측해서 만들지 마세요.\n"
    '반드시 다음 JSON 형식으로만 답하세요: {"cves": ["CVE-2026-12345"]}\n\n'
    "문서:\n"
)


def _get(path: str, timeout: float):
    url = settings.OLLAMA_URL.rstrip("/") + path
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def _post(path: str, payload: dict, timeout: float):
    url = settings.OLLAMA_URL.rstrip("/") + path
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def is_available() -> bool:
    """Ollama 서버 연결 확인(빠른 헬스체크)."""
    if settings.LLM_PROVIDER != "ollama":
        return False
    try:
        _get("/api/tags", 3)
        return True
    except Exception:
        return False


def list_models() -> list[str]:
    try:
        data = _get("/api/tags", 3)
        return [m.get("name", "") for m in data.get("models", [])]
    except Exception:
        return []


def model_present(model: str | None = None) -> bool:
    model = model or settings.LLM_MODEL
    names = list_models()
    return any(n == model or n.split(":")[0] == model.split(":")[0] for n in names)


def extract_cves(text: str) -> list[str] | None:
    """Ollama 로 CVE 코드 추출. 실패 시 None(→ 정규식 폴백)."""
    if settings.LLM_PROVIDER != "ollama" or not text:
        return None
    payload = {
        "model": settings.LLM_MODEL,
        "prompt": _PROMPT + text[:12000],
        "stream": False,
        "format": "json",
        # 추론형 모델(qwen3 등)은 thinking 토큰이 출력을 소비해 format=json 시 빈 응답을
        # 반환한다 → 비활성화. think 미지원 모델은 이 필드를 무시한다(안전).
        "think": False,
        # temperature=0(결정적) + num_thread 로 CPU 사용 제한(논리코어의 30% 기본).
        "options": {"temperature": 0, "num_thread": settings.LLM_NUM_THREAD},
    }
    try:
        data = _post("/api/generate", payload, settings.LLM_TIMEOUT_SEC)
    except Exception:
        return None
    raw = (data or {}).get("response", "") or ""
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        # 모델이 JSON 외 텍스트를 섞은 경우, 본문에서 코드만 회수.
        obj = {"cves": _CVE_RE.findall(raw)}
    codes = obj.get("cves") if isinstance(obj, dict) else None
    if not isinstance(codes, list):
        return None
    out: list[str] = []
    seen: set[str] = set()
    for c in codes:
        m = _CVE_RE.search(str(c).replace(" ", "-"))
        if m:
            code = m.group(0).upper()
            if code not in seen:
                seen.add(code)
                out.append(code)
    return out


def status() -> dict:
    avail = is_available()
    return {
        "enabled": settings.LLM_ENABLED,
        "provider": settings.LLM_PROVIDER,
        "url": settings.OLLAMA_URL,
        "model": settings.LLM_MODEL,
        "available": avail,
        "model_present": model_present() if avail else False,
        "models": list_models() if avail else [],
    }
