"""All-in-one(Python 포함) 번들 생성 — 타깃에 설치 없이 압축만 풀고 start.bat.

구성: Windows amd64 임베디드 Python + 의존성 사전설치(runtime/site) + 앱 + web + 샘플.
타깃 요건: **Windows amd64.** (Python 설치 불필요. 외부망 접속 0건.)

지원 런타임: Python 3.12 / 3.13 — 둘 다 같은 앱 코드로 빌드된다(PY_RUNTIMES 참고).

빌드 호스트: **아무 OS·아무 파이썬 버전이나 된다.** 휠은 호스트가 아니라 타깃 런타임
(cp312/cp313 · win_amd64) 기준으로 받으므로 리눅스에서 빌드해도 타깃과 ABI 가 맞는다.

Usage:
  python build_allinone.py                    # 기본(3.12) 온라인 빌드
  python build_allinone.py --python 3.13
  python build_allinone.py --python all       # 3.12 · 3.13 둘 다
  python build_allinone.py --python all --offline
      → 인터넷 없이 vendor/bundle 의 사전 수집 자산만으로 빌드.
        수집은 인터넷 PC 에서 scripts/collect_offline_bundle.py 한 번.

Output: ../advisory-platform_allinone-py312.zip (버전별)
"""
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CACHE = ROOT / "_cache"
#: 오프라인 빌드용 사전 수집 자산 루트 — scripts/collect_offline_bundle.py 가 채운다.
#: (venv 경로가 쓰는 vendor/wheels 와 일부러 분리한다. 그쪽은 호스트 ABI 기준 평평한
#:  디렉터리이고, 여기는 타깃 ABI 별로 나뉘어 있어 섞이면 안 된다.)
OFFLINE_DIR = ROOT / "vendor" / "bundle"
PYPLAT = "win_amd64"                        # 타깃 플랫폼(임베디드가 amd64)
STAGE = ROOT.parent / "_advisory_allinone_stage"
PREFIX = "advisory-platform"
REQUIREMENTS = ROOT / "requirements-bundle.txt"

INCLUDE_TOP = {"app", "web", "samples", "scripts", "docs", "nvd_powershell_sync",
               "README.md", "requirements.txt", "smoke_test.py"}
# 주의: 여기 이름은 경로의 '모든' 구성요소와 대조된다. 최상위 vendor/ 는 INCLUDE_TOP 에
# 없어 애초에 복사되지 않으므로 넣지 말 것 — 넣으면 web/public/vendor(React·Pretendard)까지
# 함께 빠져 폐쇄망에서 관리자 화면이 깨진다(외부 CDN 폴백이 없다).
SKIP_DIR = {".venv", "__pycache__", "data", ".claude", ".git", "_cache",
            "_advisory_allinone_stage"}
SKIP_EXT = {".pyc", ".pyo", ".log"}


@dataclass(frozen=True)
class Runtime:
    """번들에 넣을 임베디드 파이썬 하나.

    sha256 은 python.org 공식 배포본의 해시다. 다운로드분·캐시분 모두 매번 검증한다 —
    폐쇄망으로 들어갈 런타임이므로 중간에 바뀐 파일을 조용히 통과시키면 안 된다.
    """

    minor: str      # "3.12"  — pip --python-version
    full: str       # "3.12.10"
    sha256: str
    size: int       # 바이트(빠른 사전 판별용, 검증의 근거는 sha256)

    @property
    def abi(self) -> str:               # "cp312" — 휠 ABI 태그
        return "cp" + self.minor.replace(".", "")

    @property
    def embed_name(self) -> str:
        return f"python-{self.full}-embed-amd64.zip"

    @property
    def embed_url(self) -> str:
        return f"https://www.python.org/ftp/python/{self.full}/{self.embed_name}"

    @property
    def out_zip(self) -> Path:
        return ROOT.parent / f"advisory-platform_allinone-py{self.minor.replace('.', '')}.zip"

    @property
    def wheel_dir(self) -> Path:
        return OFFLINE_DIR / self.abi


#: 지원 런타임 고정표. 올릴 때는 sha256 도 함께 갱신할 것
#: (`python scripts/collect_offline_bundle.py --print-hashes` 가 새 값을 뽑아 준다).
PY_RUNTIMES: dict[str, Runtime] = {
    "3.12": Runtime("3.12", "3.12.10",
                    "4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3",
                    11_133_606),
    "3.13": Runtime("3.13", "3.13.7",
                    "f6cca216a359be84797cabb54149ce5e062afb16cc7567eb7fc51cacb2d86b65",
                    10_922_561),
}
DEFAULT_PY = "3.12"


def log(m: str) -> None:
    print(f"[allinone] {m}", flush=True)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def download_embed(rt: Runtime, offline: bool) -> Path:
    """임베디드 런타임 zip 확보 — 오프라인 자산 → 캐시 → 다운로드 순. 항상 해시 검증."""
    for src in (OFFLINE_DIR / rt.embed_name, CACHE / rt.embed_name):
        if not src.exists():
            continue
        got = sha256_of(src)
        if got == rt.sha256:
            log(f"embed ok (cached): {src.relative_to(ROOT) if ROOT in src.parents else src}")
            return src
        sys.exit(f"[allinone] {src} 해시 불일치 — 파일이 손상/변조됐습니다.\n"
                 f"  expected {rt.sha256}\n  actual   {got}\n"
                 f"  파일을 지우고 다시 받으세요.")

    if offline:
        sys.exit(f"[allinone] 오프라인 빌드인데 런타임이 없습니다: {OFFLINE_DIR / rt.embed_name}\n"
                 f"  인터넷 PC 에서  python scripts/collect_offline_bundle.py --python {rt.minor}\n"
                 f"  를 실행해 vendor/bundle 을 만든 뒤 통째로 복사하세요.")

    CACHE.mkdir(exist_ok=True)
    dst = CACHE / rt.embed_name
    log(f"downloading {rt.embed_url}")
    with tempfile.NamedTemporaryFile(dir=CACHE, delete=False, suffix=".part") as tmp:
        part = Path(tmp.name)
    try:                                # 부분 다운로드가 캐시로 승격되지 않게 임시파일 경유
        urllib.request.urlretrieve(rt.embed_url, part)
        got = sha256_of(part)
        if got != rt.sha256:
            sys.exit(f"[allinone] 내려받은 {rt.embed_name} 해시 불일치 — 중단합니다.\n"
                     f"  expected {rt.sha256}\n  actual   {got}")
        part.replace(dst)
    finally:
        part.unlink(missing_ok=True)
    log(f"embed ok (sha256 verified): {dst.name}")
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
    # 관리자 셸(web/admin)과 공개 자산(web/public)이 모두 있어야 한다 —
    # 정적 마운트는 public 만 서빙하고 admin 은 세션 확인 라우트로만 나간다.
    # vendor/* 는 React·ReactDOM·Pretendard 로, 폐쇄망에는 CDN 폴백이 없어 하나만 빠져도
    # 화면이 통째로 뜨지 않는다. SKIP_DIR 실수로 누락되는 사고를 여기서 잡는다.
    for rel in ("admin/app.dc.html", "admin/history.html", "public/board.html",
                "public/login.html", "public/support.js",
                "public/vendor/react.production.min.js",
                "public/vendor/react-dom.production.min.js",
                "public/vendor/pretendard.css",
                "public/vendor/PretendardVariable.woff2"):
        if not (app / "web" / rel).exists():
            sys.exit(f"web/{rel} missing — 프론트 자산 누락")


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


def install_site(app: Path, rt: Runtime, offline: bool) -> list[str]:
    """의존성을 runtime/site 에 설치하고 설치된 배포본 이름 목록을 돌려준다.

    중요(폐쇄망 자립): 휠은 '빌드 호스트의 파이썬'이 아니라 '번들에 들어갈 임베디드 런타임'
    (cp312/cp313 · win_amd64) 기준으로 받는다. 빌드 PC 에 어떤 파이썬이 깔려 있든, 심지어
    OS 가 리눅스여도 타깃과 ABI 가 일치한다. --platform/--abi/--python-version 을 쓰려면
    --only-binary=:all: 가 필요하다(크로스 설치).
    """
    site = app / "runtime" / "site"
    site.mkdir(parents=True)
    cmd = [
        sys.executable, "-m", "pip", "install",
        "--target", str(site),
        "--only-binary=:all:",
        "--python-version", rt.minor,
        "--implementation", "cp",
        "--abi", rt.abi,
        "--platform", PYPLAT,
        "-r", str(REQUIREMENTS),
    ]
    if offline:
        if not rt.wheel_dir.is_dir() or not any(rt.wheel_dir.glob("*.whl")):
            sys.exit(f"[allinone] 오프라인 빌드인데 휠이 없습니다: {rt.wheel_dir}\n"
                     f"  인터넷 PC 에서  python scripts/collect_offline_bundle.py --python {rt.minor}")
        cmd += ["--no-index", "--find-links", str(rt.wheel_dir)]
    log(f"pip install --target runtime/site "
        f"({rt.abi}/{PYPLAT} wheels, {'offline' if offline else 'online'}"
        f" — host python={sys.version.split()[0]})")
    subprocess.check_call(cmd)
    for pc in site.rglob("__pycache__"):
        shutil.rmtree(pc, ignore_errors=True)
    return sorted(p.name for p in site.glob("*.dist-info"))


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


def write_bundle_info(app: Path, rt: Runtime, dists: list[str], offline: bool) -> None:
    """번들에 뭐가 들었는지 타깃에서도 확인 가능하게 남긴다(폐쇄망 감사·문의 대응용)."""
    lines = [
        "Advisory Platform - all-in-one bundle",
        "",
        f"embedded python : {rt.full} ({rt.abi} / {PYPLAT})",
        f"embed sha256    : {rt.sha256}",
        f"build mode      : {'offline (vendor/bundle)' if offline else 'online (PyPI)'}",
        f"build host      : {sys.platform} / python {sys.version.split()[0]}",
        "",
        "installed distributions (runtime/site):",
        *(f"  {d.removesuffix('.dist-info')}" for d in dists),
        "",
        "Target requirement: Windows amd64. No Python install, no internet needed.",
        "Run start.bat, then open http://localhost:8000",
        "",
    ]
    (app / "runtime" / "BUNDLE_INFO.txt").write_text("\r\n".join(lines), encoding="ascii",
                                                     errors="replace")


def zip_bundle(app: Path, out: Path) -> int:
    if out.exists():
        out.unlink()
    n = 0
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for p in app.rglob("*"):
            if p.is_file():
                z.write(p, f"{PREFIX}/{p.relative_to(app).as_posix()}")
                n += 1
    return n


def build_one(rt: Runtime, offline: bool) -> None:
    log(f"=== building for Python {rt.full} ({rt.abi}) ===")
    embed = download_embed(rt, offline)
    if STAGE.exists():
        shutil.rmtree(STAGE)
    app = STAGE / PREFIX
    app.mkdir(parents=True)
    copy_app(app)
    place_python(app, embed)
    dists = install_site(app, rt, offline)
    write_launcher(app)
    write_bundle_info(app, rt, dists, offline)
    n = zip_bundle(app, rt.out_zip)
    shutil.rmtree(STAGE, ignore_errors=True)
    log(f"wrote {rt.out_zip} : {n} files, {rt.out_zip.stat().st_size / 1024 / 1024:.1f} MB")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--python", default=DEFAULT_PY, choices=[*PY_RUNTIMES, "all"],
                    help=f"번들에 넣을 임베디드 파이썬 (기본 {DEFAULT_PY})")
    ap.add_argument("--offline", action="store_true",
                    help="인터넷 없이 vendor/bundle 의 사전 수집 자산만으로 빌드")
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if not REQUIREMENTS.exists():
        sys.exit(f"{REQUIREMENTS.name} 이 없습니다 — 번들 의존성 목록이 필요합니다.")
    targets = list(PY_RUNTIMES.values()) if args.python == "all" else [PY_RUNTIMES[args.python]]
    for rt in targets:
        build_one(rt, args.offline)


if __name__ == "__main__":
    main()
