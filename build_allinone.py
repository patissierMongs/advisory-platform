"""All-in-one (Python 포함) 번들 생성 — 타깃에 설치 없이 압축만 풀고 start.bat.

구성: Windows 임베디드 Python 3.12 + 의존성 사전설치(runtime/site) + 앱 + web + 샘플.
타깃 요건: Windows x64. (Python 불필요. 외부망 0.)

Usage: py build_allinone.py          (Windows / Linux / Mac 어디서든 — 타깃은 항상 Windows x64)
Output: ../advisory-platform_allinone.zip

빌드 호스트가 비-Windows 여도 된다: 휠은 어차피 임베디드 런타임(cp312/win_amd64) 기준으로
받는다. 유일한 걸림돌인 uvicorn[standard]→uvloop(유닉스 전용 마커가 '호스트' 기준으로 평가됨)는
비-Windows 호스트에서 extras 를 Windows 타깃과 동일한 집합으로 풀어써서 회피한다.
"""
from __future__ import annotations

import platform
import shutil
import subprocess
import sys
import tempfile
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
               "config",   # 설정 기본값(config/defaults/*.json) — 최초 기동 시 data/config/ 로 시드
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


def _target_requirements() -> Path:
    """설치용 요구사항 파일 경로 — 비-Windows 호스트면 uvloop 마커 문제를 우회한 사본을 만든다.

    uvicorn[standard] 의 uvloop 의존성 마커(sys_platform != 'win32')는 '빌드 호스트' 기준으로
    평가된다. Linux/Mac 호스트에서는 uvloop(win_amd64 휠 없음)을 요구하게 되어 해석이 실패하므로,
    extras 를 Windows 타깃에서 실제 설치되는 집합(colorama·httptools·python-dotenv·pyyaml·
    watchfiles·websockets — uvloop 제외)으로 풀어쓴 요구사항으로 대체한다. Windows 호스트는
    원본 requirements.txt 그대로(마커가 알아서 uvloop 를 제외).
    """
    src = ROOT / "requirements.txt"
    if platform.system() == "Windows":
        return src
    lines = []
    for raw in src.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.lower().startswith("uvicorn[standard]"):
            lines.append(line.replace("[standard]", "", 1))
            lines += ["colorama", "httptools", "python-dotenv", "pyyaml",
                      "watchfiles", "websockets"]
        else:
            lines.append(raw)
    tmp = Path(tempfile.mkstemp(suffix="-allinone-req.txt")[1])
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    log(f"non-Windows host — uvicorn[standard] 를 Windows 타깃 집합으로 풀어씀: {tmp}")
    return tmp


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
        "-r", str(_target_requirements()),
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
    """빌드 호스트 사전 점검 — 버전·OS 모두 무관.

    · 파이썬 '버전' 무관: install_site 가 임베디드 cp312/win_amd64 휠을 명시적으로 받는다.
    · 'OS'도 무관: 비-Windows 호스트의 uvicorn[standard]→uvloop 마커 문제는
      _target_requirements 가 extras 를 Windows 타깃 집합으로 풀어써 우회한다.
      (타깃은 언제나 Windows x64 — 산출물은 동일하다.)
    """
    if platform.system() != "Windows":
        log(f"non-Windows build host({platform.system()}) — 타깃(win_amd64) 휠 교차 해석으로 진행")


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
