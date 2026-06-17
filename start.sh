#!/usr/bin/env bash
# 보안권고문 처리 시스템 — Linux/Mac 실행 스크립트
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "[setup] 가상환경 생성..."
  python3 -m venv .venv
fi
source .venv/bin/activate

echo "[setup] 의존성 설치..."
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt

echo "[run] http://localhost:8000  (UI: http://localhost:8000/ )"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
