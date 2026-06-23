#!/usr/bin/env python3
"""올인원 번들 휠 해석 점검 — 빌드 호스트 파이썬 '버전/OS'와 무관하게,
타깃 임베디드 런타임(cp312 / win_amd64)용 바이너리 휠이 올바로 해석되는지 확인한다.

배경: build_allinone.py 의 install_site 는 빌드 PC 의 파이썬(예: 3.11)이 아니라
임베디드 cp312/win_amd64 기준으로 휠을 받는다. 이 스크립트는 그 메커니즘이 동작함을
'실제 빌드(Windows 전용) 없이' 어디서나 검증한다. (uvicorn[standard]→uvloop 의
유닉스 전용 마커 문제를 피하기 위해, 바이너리 핵심 의존성 집합으로 점검한다.)

사용: python scripts/verify_bundle_wheels.py
종료코드 0=통과, 1=실패.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

PYMINOR = "3.12"          # 임베디드 런타임 마이너 버전 (build_allinone.PYVER 와 일치)
PYABI = "cp312"
PYPLAT = "win_amd64"

# 바이너리(.pyd) 휠이 ABI 일치해야 하는 핵심 의존성 — 이들이 cp312/win_amd64 로 와야 한다.
MUST_BE_WIN_BINARY = ("pydantic_core", "sqlalchemy", "pypdfium2", "greenlet")
# 점검용 설치 집합(uvicorn[standard]의 uvloop 회피 위해 plain uvicorn).
PROBE = ["fastapi", "uvicorn", "SQLAlchemy", "pydantic", "python-multipart",
         "pypdf", "pypdfium2", "openpyxl"]


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [
            sys.executable, "-m", "pip", "download", "--only-binary=:all:",
            "--python-version", PYMINOR, "--implementation", "cp",
            "--abi", PYABI, "--platform", PYPLAT,
            "-d", tmp, *PROBE,
        ]
        print(f"[verify] host python = {sys.version.split()[0]}")
        print(f"[verify] target wheels = {PYABI}/{PYPLAT}")
        print("[verify] $", " ".join(cmd))
        r = subprocess.run(cmd)
        if r.returncode != 0:
            print("[verify] FAIL — pip 가 타깃 휠을 해석하지 못했습니다.")
            return 1

        wheels = sorted(p.name for p in Path(tmp).glob("*.whl"))
        print("[verify] downloaded wheels:")
        for w in wheels:
            print("   ", w)

        ok = True
        for pkg in MUST_BE_WIN_BINARY:
            match = [w for w in wheels if w.lower().startswith(pkg.lower().replace("-", "_"))]
            if not match:
                print(f"[verify] FAIL — {pkg} 휠이 없습니다.")
                ok = False
                continue
            if not any(PYPLAT in w for w in match):
                print(f"[verify] FAIL — {pkg} 가 {PYPLAT} 휠이 아닙니다: {match}")
                ok = False
            else:
                print(f"[verify] OK   — {pkg}: {match[0]}")

    if ok:
        print(f"\n[verify] PASS — 빌드 호스트({sys.version.split()[0]})와 무관하게 "
              f"임베디드 {PYABI}/{PYPLAT} 휠이 올바로 해석됩니다.")
        return 0
    print("\n[verify] FAIL — 위 항목을 확인하세요.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
