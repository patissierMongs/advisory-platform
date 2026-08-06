#!/usr/bin/env python3
"""올인원 번들 휠 해석 점검 — 빌드 호스트의 파이썬 '버전/OS' 와 무관하게,
타깃 임베디드 런타임(cp312 · cp313 / win_amd64)용 바이너리 휠이 올바로 해석되는지 확인한다.

배경: build_allinone.py 의 install_site 는 빌드 PC 의 파이썬이 아니라 임베디드 런타임 기준으로
휠을 받는다. 이 스크립트는 그 메커니즘이 실제로 동작함을 '번들을 만들지 않고' 어디서나 검증한다.

함께 점검하는 것:
  · requirements-bundle.txt 가 requirements.txt 의 모든 패키지를 덮는가(드리프트 방지).
  · 지원 런타임마다 pip 이 win_amd64 휠 집합을 해석하는가.
  · 바이너리(.pyd) 의존성이 순수 파이썬 폴백이 아닌 win_amd64 휠로 오는가.

사용:
    python scripts/verify_bundle_wheels.py              # 지원 런타임 전부
    python scripts/verify_bundle_wheels.py --python 3.13
종료코드 0=통과, 1=실패.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from build_allinone import PY_RUNTIMES, PYPLAT, REQUIREMENTS, ROOT, Runtime  # noqa: E402

# 바이너리(.pyd) 휠이 ABI 일치해야 하는 핵심 의존성 — 이들이 반드시 win_amd64 로 와야 한다.
# 하나라도 순수 파이썬/sdist 로 대체되면 타깃에서 import 가 깨지거나 조용히 느려진다.
MUST_BE_WIN_BINARY = ("pydantic_core", "sqlalchemy", "pypdfium2", "greenlet")

_NAME = re.compile(r"^\s*([A-Za-z0-9._-]+)")


def _requirement_names(path: Path) -> set[str]:
    names = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        m = _NAME.match(line)
        if m:                        # extras 는 무시하고 배포본 이름만 — 정규화해 비교
            names.add(m.group(1).lower().replace("_", "-"))
    return names


def check_requirements_drift() -> bool:
    """requirements.txt 에 추가된 패키지가 번들 목록에서 누락되지 않았는지."""
    base = _requirement_names(ROOT / "requirements.txt")
    bundle = _requirement_names(REQUIREMENTS)
    missing = base - bundle
    if missing:
        print(f"[verify] FAIL — requirements.txt 에는 있는데 {REQUIREMENTS.name} 에 없습니다: "
              f"{sorted(missing)}")
        print("[verify]        번들에 그 패키지가 빠진 채 폐쇄망으로 나갑니다. 목록을 맞추세요.")
        return False
    print(f"[verify] OK   — 의존성 목록 일치 (requirements.txt {len(base)}개 ⊆ "
          f"{REQUIREMENTS.name} {len(bundle)}개)")
    return True


def check_runtime(rt: Runtime) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        cmd = [
            sys.executable, "-m", "pip", "download", "--only-binary=:all:",
            "--python-version", rt.minor, "--implementation", "cp",
            "--abi", rt.abi, "--platform", PYPLAT,
            "-d", tmp, "-r", str(REQUIREMENTS),
        ]
        print(f"\n[verify] --- Python {rt.full} ({rt.abi}/{PYPLAT}) ---")
        print("[verify] $", " ".join(cmd))
        if subprocess.run(cmd).returncode != 0:
            print(f"[verify] FAIL — pip 가 {rt.abi} 타깃 휠을 해석하지 못했습니다.")
            return False

        wheels = sorted(p.name for p in Path(tmp).glob("*.whl"))
        print(f"[verify] {len(wheels)}개 휠 해석됨")

        ok = True
        for pkg in MUST_BE_WIN_BINARY:
            match = [w for w in wheels if w.lower().startswith(pkg.lower().replace("-", "_"))]
            if not match:
                print(f"[verify] FAIL — {pkg} 휠이 없습니다.")
                ok = False
            elif not any(PYPLAT in w for w in match):
                print(f"[verify] FAIL — {pkg} 가 {PYPLAT} 휠이 아닙니다: {match}")
                ok = False
            else:
                print(f"[verify] OK   — {pkg}: {match[0]}")
        return ok


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--python", default="all", choices=[*PY_RUNTIMES, "all"])
    args = ap.parse_args()

    print(f"[verify] host python = {sys.version.split()[0]} ({sys.platform})")
    ok = check_requirements_drift()
    targets = list(PY_RUNTIMES.values()) if args.python == "all" else [PY_RUNTIMES[args.python]]
    for rt in targets:
        ok = check_runtime(rt) and ok

    if ok:
        names = ", ".join(rt.full for rt in targets)
        print(f"\n[verify] PASS — 빌드 호스트와 무관하게 임베디드 {names} / {PYPLAT} 휠이 "
              f"올바로 해석됩니다.")
        return 0
    print("\n[verify] FAIL — 위 항목을 확인하세요.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
