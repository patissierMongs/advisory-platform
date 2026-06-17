"""시스템/LLM 상태."""
from __future__ import annotations

from fastapi import APIRouter

from ..core import llm

router = APIRouter(prefix="/api/v1", tags=["system"])


@router.get("/llm/status")
def llm_status():
    """로컬 LLM(Ollama) 연결·모델 상태. 폐쇄망 점검·UI 표시용."""
    return llm.status()
