#!/usr/bin/env bash
# ── 로컬 LLM(Ollama) 포터블 설정 ──
# 사용법:  scripts/setup_llm.sh [모델명]   (기본: qwen2.5:7b)
set -e
MODEL="${1:-qwen3:8b}"

if ! command -v ollama >/dev/null 2>&1; then
  echo "[!] Ollama 미설치. https://ollama.com/download 설치 후 다시 실행하세요."
  exit 1
fi

echo "[setup] Ollama 서비스 확인..."
(ollama serve >/dev/null 2>&1 &) || true
sleep 1

echo "[setup] 모델 다운로드: $MODEL  (최초 1회, 수 GB)"
ollama pull "$MODEL"

cat <<EOF

[완료] LLM CVE 추출을 켜려면:
    export ADVISORY_LLM_ENABLED=true
    export ADVISORY_LLM_MODEL=$MODEL
그런 다음 ./start.sh 로 서버 실행.
상태 확인: http://localhost:8000/api/v1/llm/status
EOF
