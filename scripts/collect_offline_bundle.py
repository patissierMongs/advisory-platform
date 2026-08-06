#!/usr/bin/env python3
"""올인원 번들 오프라인 자산 수집 — 인터넷 되는 PC 에서 **딱 한 번** 실행.

폐쇄망 반입 절차에서 인터넷이 필요한 유일한 단계다. 여기서 만든 `vendor/bundle` 을
프로젝트 폴더와 함께 복사해 가면, 폐쇄망 안에서

    python build_allinone.py --python all --offline

로 외부망 접속 0건 상태로 올인원 zip 을 만들 수 있다.

수집물(`vendor/bundle/`):
    python-3.12.10-embed-amd64.zip      임베디드 런타임(해시 검증됨)
    python-3.13.7-embed-amd64.zip
    cp312/*.whl                          타깃 win_amd64 휠
    cp313/*.whl
    MANIFEST.sha256                      전체 목록·해시(반입 후 무결성 확인용)

실행 호스트는 **아무 OS·아무 파이썬 버전**이나 된다 — 휠은 호스트가 아니라 타깃
(cp312/cp313 · win_amd64) 기준으로 받는다.

사용:
    python scripts/collect_offline_bundle.py                 # 3.12 · 3.13 모두 수집
    python scripts/collect_offline_bundle.py --python 3.13
    python scripts/collect_offline_bundle.py --verify        # 반입 후 무결성 확인(오프라인)
    python scripts/collect_offline_bundle.py --print-hashes 3.12.11 3.13.8
                                                             # 런타임 판올림 시 새 해시 산출

종료코드 0=성공, 1=실패.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from build_allinone import (  # noqa: E402  (경로 주입 후 임포트)
    OFFLINE_DIR,
    PY_RUNTIMES,
    PYPLAT,
    REQUIREMENTS,
    Runtime,
    sha256_of,
)

MANIFEST = OFFLINE_DIR / "MANIFEST.sha256"


def log(m: str) -> None:
    print(f"[collect] {m}", flush=True)


def fetch_embed(rt: Runtime) -> bool:
    dst = OFFLINE_DIR / rt.embed_name
    if dst.exists():
        if sha256_of(dst) == rt.sha256:
            log(f"이미 있음(해시 일치): {dst.name}")
            return True
        log(f"해시 불일치 — 다시 받습니다: {dst.name}")
        dst.unlink()

    log(f"다운로드: {rt.embed_url}")
    with tempfile.NamedTemporaryFile(dir=OFFLINE_DIR, delete=False, suffix=".part") as tmp:
        part = Path(tmp.name)
    try:
        urllib.request.urlretrieve(rt.embed_url, part)
        got = sha256_of(part)
        if got != rt.sha256:
            log(f"FAIL — {rt.embed_name} 해시 불일치\n"
                f"        expected {rt.sha256}\n        actual   {got}")
            return False
        part.replace(dst)
    except OSError as exc:
        log(f"FAIL — 다운로드 실패: {exc}")
        return False
    finally:
        part.unlink(missing_ok=True)
    log(f"OK (sha256 검증): {dst.name}")
    return True


def fetch_wheels(rt: Runtime) -> bool:
    """타깃 ABI 별 휠을 받는다. 호스트 파이썬/OS 와 무관하게 win_amd64 휠만 모인다."""
    out = rt.wheel_dir
    out.mkdir(parents=True, exist_ok=True)
    cmd = [
        sys.executable, "-m", "pip", "download",
        "--only-binary=:all:",
        "--python-version", rt.minor,
        "--implementation", "cp",
        "--abi", rt.abi,
        "--platform", PYPLAT,
        "-d", str(out),
        "-r", str(REQUIREMENTS),
    ]
    log(f"휠 수집 → {out.name}/  ({rt.abi}/{PYPLAT})")
    if subprocess.run(cmd).returncode != 0:
        log("FAIL — pip download 실패(인터넷/프록시/방화벽 확인).")
        return False
    n = len(list(out.glob("*.whl")))
    log(f"OK — {n}개 휠")
    return n > 0


def write_manifest() -> None:
    rows: list[str] = []
    for p in sorted(OFFLINE_DIR.rglob("*")):
        if p.is_file() and p != MANIFEST and p.suffix != ".part":
            rows.append(f"{sha256_of(p)}  {p.relative_to(OFFLINE_DIR).as_posix()}")
    MANIFEST.write_text("\n".join(rows) + "\n", encoding="ascii")
    log(f"MANIFEST.sha256 기록 — {len(rows)}개 파일")


def verify() -> int:
    """반입 후(폐쇄망 안) 무결성 확인 — USB 전송 중 손상/누락을 잡는다."""
    if not MANIFEST.exists():
        log(f"FAIL — {MANIFEST} 가 없습니다. 인터넷 PC 에서 먼저 수집하세요.")
        return 1
    bad = 0
    seen: set[str] = set()
    for line in MANIFEST.read_text(encoding="ascii").splitlines():
        if not line.strip():
            continue
        want, rel = line.split("  ", 1)
        seen.add(rel)
        target = OFFLINE_DIR / rel
        if not target.exists():
            log(f"FAIL — 누락: {rel}")
            bad += 1
        elif sha256_of(target) != want:
            log(f"FAIL — 해시 불일치: {rel}")
            bad += 1
    extra = {p.relative_to(OFFLINE_DIR).as_posix() for p in OFFLINE_DIR.rglob("*")
             if p.is_file() and p != MANIFEST} - seen
    for rel in sorted(extra):
        log(f"WARN — 목록에 없는 파일: {rel}")
    if bad:
        log(f"FAIL — {bad}건 불일치. 자산을 다시 복사하세요.")
        return 1
    log(f"PASS — {len(seen)}개 파일 무결성 확인. 이제 오프라인 빌드가 가능합니다:")
    log("       python build_allinone.py --python all --offline")
    return 0


def print_hashes(versions: list[str]) -> int:
    """런타임 판올림용 — 임의 버전의 임베디드 zip 해시를 받아 PY_RUNTIMES 행으로 찍는다."""
    OFFLINE_DIR.mkdir(parents=True, exist_ok=True)
    rc = 0
    for full in versions:
        minor = ".".join(full.split(".")[:2])
        url = f"https://www.python.org/ftp/python/{full}/python-{full}-embed-amd64.zip"
        log(f"해시 산출: {url}")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zip") as tmp:
            part = Path(tmp.name)
        try:
            urllib.request.urlretrieve(url, part)
            print(f'    "{minor}": Runtime("{minor}", "{full}",\n'
                  f'                    "{sha256_of(part)}",\n'
                  f'                    {part.stat().st_size:_}),')
        except OSError as exc:
            log(f"FAIL — {full}: {exc}")
            rc = 1
        finally:
            part.unlink(missing_ok=True)
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--python", default="all", choices=[*PY_RUNTIMES, "all"],
                    help="수집할 타깃 파이썬 (기본 all — 3.12·3.13 모두)")
    ap.add_argument("--verify", action="store_true",
                    help="수집물 무결성만 확인(오프라인, 폐쇄망 반입 후 실행)")
    ap.add_argument("--print-hashes", nargs="+", metavar="X.Y.Z",
                    help="런타임 판올림 시 새 임베디드 zip 의 PY_RUNTIMES 행을 출력")
    args = ap.parse_args()

    if args.print_hashes:
        return print_hashes(args.print_hashes)
    if args.verify:
        return verify()

    OFFLINE_DIR.mkdir(parents=True, exist_ok=True)
    targets = list(PY_RUNTIMES.values()) if args.python == "all" else [PY_RUNTIMES[args.python]]
    for rt in targets:
        log(f"=== Python {rt.full} ({rt.abi}) ===")
        if not fetch_embed(rt) or not fetch_wheels(rt):
            log("FAIL — 수집이 완료되지 않았습니다.")
            return 1

    write_manifest()
    log(f"완료 — '{OFFLINE_DIR}' 를 프로젝트와 함께 폐쇄망으로 복사하세요.")
    log("       복사 후 폐쇄망에서:  python scripts/collect_offline_bundle.py --verify")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
