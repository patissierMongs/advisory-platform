"""All-in-one (Python 포함) 번들 생성 — 타깃에 설치 없이 압축만 풀고 start.bat.

구성: Windows 임베디드 Python 3.12 + 의존성 사전설치(runtime/site) + 앱 + web + 샘플.
타깃 요건: Windows x64. (Python 불필요. 외부망 0. LLM은 선택.)

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
EMBED_URL = f"https://www.python.org/ftp/python/{PYVER}/python-{PYVER}-embed-amd64.zip"
STAGE = ROOT.parent / "_advisory_allinone_stage"
OUT = ROOT.parent / "advisory-platform_allinone.zip"
PREFIX = "advisory-platform"

INCLUDE_TOP = {"app", "web", "samples", "scripts", "docs",
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
    log("pip install --target runtime/site (cp312 wheels)")
    subprocess.check_call([
        sys.executable, "-m", "pip", "install", "--target", str(site),
        "-r", str(ROOT / "requirements.txt"),
    ])
    for pc in site.rglob("__pycache__"):
        shutil.rmtree(pc, ignore_errors=True)


def write_launcher(app: Path) -> None:
    # ASCII 전용(.bat 한글은 cp949에서 깨짐) — 화면 안내는 영문, 앱 UI는 한국어.
    (app / "start.bat").write_text(
        "@echo off\r\n"
        "title Advisory Platform\r\n"
        "cd /d \"%~dp0\"\r\n"
        "echo Starting Advisory Platform -- open http://localhost:8000 in a browser.\r\n"
        "\"%~dp0runtime\\python\\python.exe\" -m uvicorn app.main:app --host 0.0.0.0 --port 8000\r\n"
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


def main() -> None:
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
