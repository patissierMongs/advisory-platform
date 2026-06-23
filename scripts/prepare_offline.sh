#!/usr/bin/env bash
# 오프라인 배포 준비 — 인터넷 되는 PC에서 '단 한 번' 실행한다.
# requirements.txt 의존성을 휠(.whl)로 내려받아 vendor/wheels 에 모은다.
# 이후 프로젝트 폴더(+ vendor/wheels)를 폐쇄망 타깃으로 복사하면, start.sh 가
# 외부망 없이 --no-index 로 설치한다. (이 스크립트만 온라인이 필요하다.)
set -e
cd "$(dirname "$0")/.."

WHEELS="${ADVISORY_WHEELS_DIR:-vendor/wheels}"
mkdir -p "$WHEELS"

echo "[prepare] requirements.txt 휠 수집 → $WHEELS"
python3 -m pip download -r requirements.txt -d "$WHEELS"
# 타깃에서 pip/setuptools/wheel 부재 시를 대비해 빌드 백엔드도 함께 수집.
python3 -m pip download pip setuptools wheel -d "$WHEELS" || true

echo "[prepare] 완료. '$WHEELS' 를 프로젝트와 함께 폐쇄망으로 복사하세요."
echo "[prepare] 주의: 타깃과 동일한 OS/CPU/파이썬(예: Linux x86_64, cp312)에서 실행해야"
echo "[prepare]       바이너리 휠(pypdfium2 등)이 타깃에서 호환됩니다."
