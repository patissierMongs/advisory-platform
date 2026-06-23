#!/usr/bin/env bash
# 보안권고문 처리 시스템 — Linux/Mac 실행 스크립트
# 폐쇄망(인터넷 없음) 기본 전제: 실행 경로는 외부망을 절대 타지 않는다.
#  · 의존성은 로컬 오프라인 휠(vendor/wheels)에서만 설치한다.
#  · 휠을 모으는 단 한 번의 온라인 작업은 scripts/prepare_offline.sh 로 분리했다.
#  · 개발 PC에서 굳이 PyPI로 설치하려면 ADVISORY_ONLINE_INSTALL=1 을 명시해야 한다.
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "[setup] 가상환경 생성..."
  python3 -m venv .venv
fi
source .venv/bin/activate

# 이미 설치돼 있으면 건너뜀(오프라인에서 매 실행마다 설치 시도하지 않음).
if ! python -c "import uvicorn" >/dev/null 2>&1; then
  WHEELS="${ADVISORY_WHEELS_DIR:-vendor/wheels}"
  if [ -d "$WHEELS" ] && ls "$WHEELS"/*.whl >/dev/null 2>&1; then
    echo "[setup] 오프라인 휠에서 설치: $WHEELS (외부망 미사용)"
    python -m pip install -q --no-index --find-links "$WHEELS" -r requirements.txt
  elif [ "${ADVISORY_ONLINE_INSTALL:-0}" = "1" ]; then
    echo "[setup] 온라인 설치(PyPI) — ADVISORY_ONLINE_INSTALL=1 명시됨"
    python -m pip install -q --upgrade pip
    python -m pip install -q -r requirements.txt
  else
    echo "[ERROR] 의존성이 없고 오프라인 휠($WHEELS)도 없습니다." >&2
    echo "        폐쇄망: 인터넷 되는 PC에서 'scripts/prepare_offline.sh' 를 실행해" >&2
    echo "        생성된 'vendor/wheels' 디렉터리를 이 폴더와 함께 복사하세요." >&2
    echo "        (개발 PC에서 PyPI 온라인 설치가 필요하면: ADVISORY_ONLINE_INSTALL=1 ./start.sh)" >&2
    exit 1
  fi
fi

echo "[run] http://localhost:8000  (UI: http://localhost:8000/ )"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
