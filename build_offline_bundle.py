"""완전 자립형 오프라인 번들(코드+임베드Python+의존성+CPU Ollama+qwen3.5:4b) 생성.

"압축만 풀면 다 돌아가게" — 타깃(Windows x64)에 아무 설치 없이 압축 해제 후 start.bat 만 실행.
구성:
  runtime/python   임베디드 Python 3.12.8 (_cache 의 embed zip)
  runtime/site     의존성(.venv/Lib/site-packages 오프라인 복사 — 버전 동일)
  app web ...      앱 소스
  ollama           CPU 전용 Ollama 런타임(GPU 러너 cuda/rocm/vulkan 제외 → ~70MB)
  ollama-models    qwen3.5:4b manifest + blobs
  start.bat        Ollama serve + uvicorn 자동 기동(LLM 활성)

사용:
  .venv/Scripts/python.exe build_offline_bundle.py stage   # 스테이지 빌드(검증용)
  .venv/Scripts/python.exe build_offline_bundle.py zip      # 스테이지를 zip 으로
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOME = Path(os.environ.get("USERPROFILE") or Path.home())
LOCALAPPDATA = Path(os.environ.get("LOCALAPPDATA", HOME / "AppData" / "Local"))

OLLAMA_SRC = LOCALAPPDATA / "Programs" / "Ollama"
MODELS_SRC = HOME / ".ollama" / "models"
MODEL_MANIFEST_REL = "manifests/registry.ollama.ai/library/qwen3.5/4b"
VENV_SITE = ROOT / ".venv" / "Lib" / "site-packages"
EMBED_ZIP = ROOT / "_cache" / "python-3.12.8-embed-amd64.zip"

STAGE = ROOT.parent / "_advisory_offline_stage"
APP = STAGE / "advisory-platform"
OUT = ROOT.parent / "advisory-platform_offline_qwen3.5.zip"
PREFIX = "advisory-platform"

INCLUDE_TOP = {"app", "web", "samples", "scripts", "docs",
               "README.md", "requirements.txt", "smoke_test.py", "build_allinone.py"}
SKIP_DIR = {".venv", "__pycache__", "data", ".claude", ".git", "_cache",
            ".ds-build", "ds-bundle", ".design-sync"}
SKIP_EXT = {".pyc", ".pyo", ".log"}
GPU_DIRS = {"cuda_v12", "cuda_v13", "cuda_v11", "rocm_v7_1", "rocm", "vulkan"}  # CPU 전용: 제외


def log(m):
    print(f"[offline] {m}", flush=True)


def _copy_tree(src: Path, dst: Path, skip_dirs=(), skip_ext=()):
    n = 0
    for p in src.rglob("*"):
        if p.is_dir():
            continue
        rel = p.relative_to(src)
        if any(part in skip_dirs for part in rel.parts) or p.suffix in skip_ext:
            continue
        d = dst / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, d)
        n += 1
    return n


def stage_app():
    for top in INCLUDE_TOP:
        src = ROOT / top
        if not src.exists():
            continue
        if src.is_file():
            shutil.copy2(src, APP / top)
        else:
            _copy_tree(src, APP / top, SKIP_DIR, SKIP_EXT)
    assert (APP / "web" / "app.dc.html").exists(), "web/app.dc.html 누락"
    log("app 소스 복사 완료")


def stage_python():
    pyd = APP / "runtime" / "python"
    pyd.mkdir(parents=True)
    with zipfile.ZipFile(EMBED_ZIP) as z:
        z.extractall(pyd)
    pth = next(pyd.glob("python*._pth"))
    lines = pth.read_text(encoding="ascii").splitlines()
    for extra in ("..\\site", "..\\.."):
        if extra not in lines:
            lines.append(extra)
    pth.write_text("\n".join(lines) + "\n", encoding="ascii")
    log(f"embed python 배치 + {pth.name} 패치")


def stage_deps():
    site = APP / "runtime" / "site"
    n = _copy_tree(VENV_SITE, site, skip_dirs={"__pycache__"}, skip_ext={".pyc", ".pyo"})
    log(f"의존성 {n}개 파일 복사(runtime/site)")


def stage_ollama():
    dst = APP / "ollama"
    (dst / "lib" / "ollama").mkdir(parents=True)
    shutil.copy2(OLLAMA_SRC / "ollama.exe", dst / "ollama.exe")
    libsrc = OLLAMA_SRC / "lib" / "ollama"
    n = 0
    for p in libsrc.rglob("*"):
        if p.is_dir():
            continue
        rel = p.relative_to(libsrc)
        if rel.parts and rel.parts[0] in GPU_DIRS:   # GPU 러너 제외
            continue
        d = dst / "lib" / "ollama" / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, d)
        n += 1
    sz = sum(f.stat().st_size for f in dst.rglob("*") if f.is_file())
    log(f"Ollama(CPU 전용) 복사: {n + 1}개 파일, {sz/1e6:.0f} MB")


def stage_model():
    man = MODELS_SRC / MODEL_MANIFEST_REL
    data = json.loads(man.read_text())
    digests = [data["config"]["digest"]] + [l["digest"] for l in data["layers"]]
    # manifest
    dman = APP / "ollama-models" / MODEL_MANIFEST_REL
    dman.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(man, dman)
    # blobs
    bdst = APP / "ollama-models" / "blobs"
    bdst.mkdir(parents=True, exist_ok=True)
    tot = 0
    for dg in digests:
        fn = dg.replace(":", "-")
        src = MODELS_SRC / "blobs" / fn
        shutil.copy2(src, bdst / fn)
        tot += src.stat().st_size
    log(f"qwen3.5:4b 모델 복사: blob {len(digests)}개, {tot/1e9:.2f} GB")


def stage_launcher():
    # CPU 사용 제한: 논리코어의 30%만 쓰도록 affinity 마스크 계산(헥스, 0x 없이).
    (APP / "cpu_mask.py").write_text(
        "import os\n"
        "n = os.cpu_count() or 4\n"
        "k = max(1, round(n * 0.3))   # 30% of logical cores\n"
        "print(format((1 << k) - 1, 'x'))   # hex affinity mask for start /affinity\n",
        encoding="ascii",
    )
    # goto 분기 사용 — 괄호 블록(echo 안 괄호가 블록을 조기 종료시키는 문제) 회피. 변수는 단일 %.
    (APP / "start.bat").write_text(
        "@echo off\r\n"
        "title Advisory Platform - offline + qwen3.5:4b\r\n"
        "cd /d \"%~dp0\"\r\n"
        "set \"OLLAMA_HOST=127.0.0.1:21434\"\r\n"
        "set \"OLLAMA_MODELS=%~dp0ollama-models\"\r\n"
        "set \"ADVISORY_LLM_ENABLED=true\"\r\n"
        "set \"ADVISORY_OLLAMA_URL=http://127.0.0.1:21434\"\r\n"
        "set \"ADVISORY_LLM_MODEL=qwen3.5:4b\"\r\n"
        "rem Limit Ollama CPU to ~30 pct of logical cores via affinity mask (app num_thread also auto-limits).\r\n"
        "set \"OLLMASK=\"\r\n"
        "\"%~dp0runtime\\python\\python.exe\" \"%~dp0cpu_mask.py\" > \"%TEMP%\\adv_ollmask.txt\" 2>nul\r\n"
        "set /p OLLMASK=<\"%TEMP%\\adv_ollmask.txt\"\r\n"
        "echo Starting local LLM - Ollama on CPU, limited to ~30 pct of cores ...\r\n"
        "if not defined OLLMASK goto no_affinity\r\n"
        "start \"ollama\" /min /affinity %OLLMASK% \"%~dp0ollama\\ollama.exe\" serve\r\n"
        "goto llm_started\r\n"
        ":no_affinity\r\n"
        "start \"ollama\" /min \"%~dp0ollama\\ollama.exe\" serve\r\n"
        ":llm_started\r\n"
        "echo Waiting for LLM to be ready ...\r\n"
        "\"%~dp0runtime\\python\\python.exe\" \"%~dp0wait_ollama.py\"\r\n"
        "echo Starting Advisory Platform -- open http://localhost:8000 in a browser.\r\n"
        "\"%~dp0runtime\\python\\python.exe\" -m uvicorn app.main:app --host 0.0.0.0 --port 8000\r\n"
        "pause\r\n",
        encoding="ascii",
    )
    (APP / "wait_ollama.py").write_text(
        "import urllib.request, time, sys\n"
        "url = 'http://127.0.0.1:21434/api/tags'\n"
        "for _ in range(90):\n"
        "    try:\n"
        "        urllib.request.urlopen(url, timeout=1); print('LLM ready'); sys.exit(0)\n"
        "    except Exception:\n"
        "        time.sleep(1)\n"
        "print('LLM not ready (app continues with regex fallback)'); sys.exit(0)\n",
        encoding="ascii",
    )
    (APP / "READ_ME_FIRST.txt").write_text(
        "Advisory Platform - 오프라인 완전 자립형 번들 (qwen3.5:4b 포함)\r\n"
        "================================================================\r\n\r\n"
        "1) 이 폴더를 원하는 위치에 둡니다 (경로에 한글/공백 없어도 무방).\r\n"
        "2) start.bat 을 더블클릭합니다.\r\n"
        "   - 로컬 LLM(Ollama, CPU)이 먼저 뜨고, 이어서 앱이 기동됩니다.\r\n"
        "3) 브라우저에서 http://localhost:8000 접속.\r\n\r\n"
        "포함: 임베드 Python 3.12 / 모든 의존성 / 앱 / CPU용 Ollama / qwen3.5:4b 모델.\r\n"
        "요건: Windows x64. 인터넷 불필요(외부 호출 0). 권장 RAM 8GB+ (4B 모델 CPU 추론).\r\n"
        "참고: GPU 가속 라이브러리는 제외했습니다(CPU로 동작). 데이터는 data/ 에 생성됩니다.\r\n",
        encoding="utf-8",
    )
    log("런처(start.bat) + wait_ollama.py + 안내문 작성")


def build_stage():
    if STAGE.exists():
        shutil.rmtree(STAGE)
    APP.mkdir(parents=True)
    stage_app()
    stage_python()
    stage_deps()
    stage_ollama()
    stage_model()
    stage_launcher()
    sz = sum(f.stat().st_size for f in APP.rglob("*") if f.is_file())
    log(f"스테이지 완료: {APP}  (총 {sz/1e9:.2f} GB)")


def zip_stage():
    if not APP.exists():
        sys.exit("스테이지 없음 — 먼저 'stage' 실행")
    if OUT.exists():
        OUT.unlink()
    # 모델 blob/ollama 바이너리는 이미 압축형이라 STORED(빠름), 나머지는 DEFLATE.
    big_ext = {".dll", ".exe", ".pyd"}
    n = 0
    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        for p in APP.rglob("*"):
            if not p.is_file():
                continue
            rel = p.relative_to(APP).as_posix()
            arc = f"{PREFIX}/{rel}"
            is_blob = "/ollama-models/blobs/" in ("/" + rel)
            ct = zipfile.ZIP_STORED if (is_blob or p.suffix.lower() in big_ext) else zipfile.ZIP_DEFLATED
            z.write(p, arc, compress_type=ct)
            n += 1
    log(f"wrote {OUT} : {n} files, {OUT.stat().st_size/1e9:.2f} GB")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stage"
    if cmd == "stage":
        build_stage()
    elif cmd == "zip":
        zip_stage()
    elif cmd == "all":
        build_stage()
        zip_stage()
    else:
        sys.exit(f"unknown cmd: {cmd}")
