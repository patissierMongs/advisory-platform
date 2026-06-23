"""All-in-one (Python 포함) 번들 생성 — 타깃에 설치 없이 압축만 풀고 start.bat.

구성: Windows 임베디드 Python 3.12 + 의존성 사전설치(runtime/site) + 앱 + web + 샘플.
타깃 요건: Windows x64. (Python 불필요. 외부망 0.)

Usage: py -3.12 build_allinone.py
Output: ../advisory-platform_allinone.zip
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / "_cache"
PYVER = "3.12.8"
PYMINOR = ".".join(PYVER.split(".")[:2])   # "3.12" — 임베디드 런타임 마이너 버전
PYABI = "cp" + PYMINOR.replace(".", "")    # "cp312" — 휠 ABI 태그
PYPLAT = "win_amd64"                        # 타깃 플랫폼(임베디드가 amd64)
EMBED_URL = f"https://www.python.org/ftp/python/{PYVER}/python-{PYVER}-embed-amd64.zip"
STAGE = ROOT.parent / "_advisory_allinone_stage"
OUT = ROOT.parent / "advisory-platform_allinone.zip"
PREFIX = "advisory-platform"

INCLUDE_TOP = {"app", "web", "samples", "scripts", "docs", "nvd_powershell_sync",
               "README.md", "requirements.txt", "smoke_test.py"}
SKIP_DIR = {".venv", "__pycache__", "data", ".claude", ".git", "_cache",
            "_advisory_allinone_stage"}
SKIP_EXT = {".pyc", ".pyo", ".log"}


def log(m: str) -> None:
    print(f"[allinone] {m}", flush=True)


def download_embed() -> Path:
    CACHE.mkdir(exist_ok=True)
    dst = CACHE / f"python-{PYVER}-embed-amd64.zip"
    if dst.exists() and dst.stat().st_size > 1_000_000:
        log(f"embed cached: {dst.name}")
        return dst
    log(f"downloading {EMBED_URL}")
    urllib.request.urlretrieve(EMBED_URL, dst)
    return dst


def copy_app(app: Path) -> None:
    for top in INCLUDE_TOP:
        src = ROOT / top
        if not src.exists():
            continue
        if src.is_file():
            shutil.copy2(src, app / top)
            continue
        for p in src.rglob("*"):
            if p.is_dir():
                continue
            rel = p.relative_to(ROOT)
            if any(part in SKIP_DIR for part in rel.parts) or p.suffix in SKIP_EXT:
                continue
            dst = app / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst)
    if not (app / "web" / "app.dc.html").exists():
        sys.exit("web/app.dc.html missing — 프론트 자산 누락")


def place_python(app: Path, embed_zip: Path) -> None:
    pyd = app / "runtime" / "python"
    pyd.mkdir(parents=True)
    with zipfile.ZipFile(embed_zip) as z:
        z.extractall(pyd)
    pth = next(pyd.glob("python*._pth"))
    lines = pth.read_text(encoding="ascii").splitlines()
    for extra in ("..\\site", "..\\.."):  # site=의존성, ..\..=프로젝트루트(app 패키지)
        if extra not in lines:
            lines.append(extra)
    pth.write_text("\n".join(lines) + "\n", encoding="ascii")
    log(f"patched {pth.name}: + ..\\site + ..\\..")


def install_site(app: Path) -> None:
    site = app / "runtime" / "site"
    site.mkdir(parents=True)
    # 중요(폐쇄망 자립): 휠은 '빌드 호스트의 파이썬'이 아니라 '번들에 들어갈 임베디드 런타임'
    # (cp312 / win_amd64) 기준으로 받는다. 빌드 PC에 3.11 등 다른 버전이 깔려 PATH로 실행되더라도
    # 바이너리 휠(pydantic-core·pypdfium2 등)이 타깃 3.12와 ABI 일치하도록 강제한다.
    # --platform/--abi/--python-version 을 쓰려면 --only-binary=:all: 가 필요(크로스 설치).
    log(f"pip install --target runtime/site ({PYABI}/{PYPLAT} wheels — host python={sys.version.split()[0]})")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install",
        "--target", str(site),
        "--only-binary=:all:",
        "--python-version", PYMINOR,
        "--implementation", "cp",
        "--abi", PYABI,
        "--platform", PYPLAT,
        "-r", str(ROOT / "requirements.txt"),
    ])
    for pc in site.rglob("__pycache__"):
        shutil.rmtree(pc, ignore_errors=True)


def write_launcher(app: Path) -> None:
    # ASCII 전용(.bat 한글은 cp949에서 깨짐) — 화면 안내는 영문, 앱 UI는 한국어.
    # 중요(폐쇄망 자립): 타깃에 '다른 버전의 Python'이 이미 깔려 PATH/환경변수에 있어도
    # 무조건 번들 내 임베디드 런타임(절대경로)만 쓴다. 시스템 파이썬을 끌어들일 수 있는
    # PYTHONPATH/PYTHONHOME/PYTHONSTARTUP 을 비우고, 절대경로 python.exe 로 직접 실행한다.
    # (임베디드 배포는 python*._pth 로 sys.path 가 고정되어 레지스트리/PYTHONPATH 를 무시하지만,
    #  환경변수 오염을 이중으로 차단한다.)
    (app / "start.bat").write_text(
        "@echo off\r\n"
        "title Advisory Platform\r\n"
        "cd /d \"%~dp0\"\r\n"
        "set \"PYTHONPATH=\"\r\n"
        "set \"PYTHONHOME=\"\r\n"
        "set \"PYTHONSTARTUP=\"\r\n"
        "set \"PY=%~dp0runtime\\python\\python.exe\"\r\n"
        "if not exist \"%PY%\" (\r\n"
        "  echo [ERROR] Embedded Python missing: \"%PY%\"\r\n"
        "  echo   The bundle is incomplete. Re-extract the all-in-one zip.\r\n"
        "  pause\r\n"
        "  exit /b 1\r\n"
        ")\r\n"
        "echo Starting Advisory Platform -- open http://localhost:8000 in a browser.\r\n"
        "\"%PY%\" -m uvicorn app.main:app --host 0.0.0.0 --port 8000\r\n"
        "pause\r\n",
        encoding="ascii",
    )


def zip_bundle(app: Path) -> int:
    if OUT.exists():
        OUT.unlink()
    n = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        for p in app.rglob("*"):
            if p.is_file():
                z.write(p, f"{PREFIX}/{p.relative_to(app).as_posix()}")
                n += 1
    return n


def _check_build_host() -> None:
    """빌드 호스트 사전 점검.

    · 파이썬 '버전'은 무관하다 — install_site 가 임베디드 cp312/win_amd64 휠을 명시적으로 받으므로
      빌드 PC에 3.11 등 다른 버전이 깔려 PATH 로 실행돼도 타깃과 ABI 가 일치한다.
    · 다만 'OS'는 Windows 여야 한다 — requirements 의 uvicorn[standard] → uvloop(유닉스 전용)이
      비-Windows 호스트에서 환경 마커(sys_platform)상 요구돼 cross-OS 휠 해석이 실패하기 때문.
      (Windows 호스트에서는 sys_platform=='win32' 라 uvloop 이 마커로 제외되어 정상 해석된다.)
    """
    import platform

    if platform.system() != "Windows":
        sys.exit(
            "이 올인원 빌더는 Windows 에서 실행해야 합니다(임베디드 런타임=Windows, "
            "uvicorn[standard]→uvloop 마커 때문).\n"
            "  · 빌드 PC 의 파이썬 '버전'은 상관없습니다(타깃 cp312 휠을 따로 받음).\n"
            "  · Windows 에서  py build_allinone.py  로 실행하세요.\n"
            "  · 휠 해석/메커니즘만 비-Windows 에서 점검하려면 scripts/verify_bundle_wheels.py 를 사용하세요."
        )


def main() -> None:
    _check_build_host()
    embed = download_embed()
    if STAGE.exists():
        shutil.rmtree(STAGE)
    app = STAGE / PREFIX
    app.mkdir(parents=True)
    copy_app(app)
    place_python(app, embed)
    install_site(app)
    write_launcher(app)
    n = zip_bundle(app)
    log(f"wrote {OUT} : {n} files, {OUT.stat().st_size/1024/1024:.1f} MB")


if __name__ == "__main__":
    main()
