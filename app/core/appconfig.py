"""파일 기반 설정 저장소 — '모든 설정은 파일로 관리하고 웹에서 편집' 원칙의 공용 모듈.

· 실체는 data/config/<name>.json — 운영 중 편집 대상 파일. 최초 접근 시
  config/defaults/<name>.json(저장소 동봉 기본값)을 복사해 시드한다.
· 읽기는 mtime 캐시 — 웹 편집이 아니라 파일을 직접 고쳐도 다음 요청에 즉시 반영.
· 쓰기는 검증기 통과 후 원자적(tmp→replace)으로 저장한다. 깨진 설정이 남지 않는다.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

from ..config import BASE_DIR, DATA_DIR

CONFIG_DIR = DATA_DIR / "config"
DEFAULTS_DIR = BASE_DIR / "config" / "defaults"

_LOCK = threading.Lock()
_CACHE: dict[str, tuple[float, Any]] = {}   # name → (mtime, value)

_HEX_COLOR = re.compile(r"^#[0-9a-fA-F]{6}$")


def _validate_source_orgs(value: Any) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("organizations"), list):
        raise ValueError("최상위에 organizations 리스트가 필요합니다.")
    seen: set[str] = set()
    for org in value["organizations"]:
        if not isinstance(org, dict) or not str(org.get("name", "")).strip():
            raise ValueError("각 기관은 {name, aliases[]} 형식이어야 합니다.")
        name = str(org["name"]).strip()
        if name in seen:
            raise ValueError(f"기관명이 중복되었습니다: {name}")
        seen.add(name)
        aliases = org.get("aliases", [])
        if not isinstance(aliases, list) or any(not isinstance(a, str) for a in aliases):
            raise ValueError(f"{name}: aliases 는 문자열 리스트여야 합니다.")


def _validate_regex_list(patterns: Any, where: str) -> None:
    if not isinstance(patterns, list) or not patterns:
        raise ValueError(f"{where}: patterns 는 비어있지 않은 리스트여야 합니다.")
    for p in patterns:
        if not isinstance(p, str) or not p.strip():
            raise ValueError(f"{where}: 빈 패턴이 있습니다.")
        try:
            re.compile(p, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"{where}: 정규식 오류 '{p}' — {e}") from e


def _validate_product_catalog(value: Any) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("products"), list):
        raise ValueError("최상위에 products 리스트가 필요합니다.")
    seen: set[str] = set()
    for prod in value["products"]:
        if not isinstance(prod, dict):
            raise ValueError("각 제품은 객체여야 합니다.")
        key, label = str(prod.get("key", "")).strip(), str(prod.get("label", "")).strip()
        if not key or not label:
            raise ValueError("각 제품에 key 와 label 이 필요합니다.")
        if key in seen:
            raise ValueError(f"제품 key 가 중복되었습니다: {key}")
        seen.add(key)
        _validate_regex_list(prod.get("patterns"), f"제품 {label}")
        color = prod.get("color")
        if color is not None and not _HEX_COLOR.match(str(color)):
            raise ValueError(f"제품 {label}: color 는 #rrggbb 형식이어야 합니다.")
    vps = value.get("version_patterns", [])
    if not isinstance(vps, list):
        raise ValueError("version_patterns 는 리스트여야 합니다.")
    for vp in vps:
        if not isinstance(vp, dict) or not str(vp.get("name", "")).strip():
            raise ValueError("각 버전 패턴은 {name, pattern} 형식이어야 합니다.")
        _validate_regex_list([vp.get("pattern", "")], f"버전 패턴 {vp.get('name')}")
    colors = value.get("colors", {})
    if not isinstance(colors, dict):
        raise ValueError("colors 는 객체여야 합니다.")
    for k, v in colors.items():
        if not _HEX_COLOR.match(str(v)):
            raise ValueError(f"colors.{k}: #rrggbb 형식이어야 합니다.")


def _validate_product_aliases(value: Any) -> None:
    if not isinstance(value, dict) or not isinstance(value.get("aliases"), dict):
        raise ValueError("최상위에 aliases 객체(제품키 → 별칭 리스트)가 필요합니다.")
    for key, aliases in value["aliases"].items():
        if not isinstance(aliases, list) or any(not isinstance(a, str) or not a.strip() for a in aliases):
            raise ValueError(f"{key}: 별칭은 비어있지 않은 문자열 리스트여야 합니다.")


# 설정 레지스트리 — 새 설정은 여기에 이름·설명·검증기만 등록하면
# 파일 시드/조회/웹 편집(GET·PUT /api/v1/config)이 전부 따라온다.
REGISTRY: dict[str, dict[str, Any]] = {
    "source_orgs": {
        "title": "출처기관 목록",
        "description": "보안권고문 배포 기관(출처) 목록과 별칭 — 업로드 시 폴더명·파일명·본문에서 출처 자동 탐지에 사용",
        "validator": _validate_source_orgs,
    },
    "product_catalog": {
        "title": "제품·버전 추출 카탈로그",
        "description": "CVE 게이트(미등록 CVE 수동 등록) 화면의 제품 필수 리스트·버전 패턴·하이라이트 색상",
        "validator": _validate_product_catalog,
    },
    "product_aliases": {
        "title": "제품 정규화 별칭 사전",
        "description": "자산대장·CVE 피드의 제품 문자열을 동일한 product_key 로 정규화하는 별칭 사전(§4.6-1)",
        "validator": _validate_product_aliases,
    },
}


def config_path(name: str) -> Path:
    if name not in REGISTRY:
        raise KeyError(f"등록되지 않은 설정: {name}")
    return CONFIG_DIR / f"{name}.json"


def _seed_if_missing(name: str) -> Path:
    path = config_path(name)
    if not path.exists():
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        default = DEFAULTS_DIR / f"{name}.json"
        if default.exists():
            path.write_bytes(default.read_bytes())
        else:
            path.write_text("{}", encoding="utf-8")
    return path


def get_config(name: str) -> Any:
    """설정값 조회. 파일 mtime 이 바뀌면 자동 리로드(직접 파일 수정도 즉시 반영)."""
    with _LOCK:
        path = _seed_if_missing(name)
        mtime = path.stat().st_mtime
        cached = _CACHE.get(name)
        if cached and cached[0] == mtime:
            return cached[1]
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise ValueError(f"설정 파일 파싱 실패({path.name}): {e}") from e
        _CACHE[name] = (mtime, value)
        return value


def save_config(name: str, value: Any) -> Any:
    """검증 후 원자적 저장. 반환은 저장된 값."""
    entry = REGISTRY.get(name)
    if entry is None:
        raise KeyError(f"등록되지 않은 설정: {name}")
    validator: Callable[[Any], None] | None = entry.get("validator")
    if validator:
        validator(value)
    with _LOCK:
        path = config_path(name)
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(CONFIG_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as out:
                json.dump(value, out, ensure_ascii=False, indent=2)
                out.write("\n")
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
        _CACHE[name] = (path.stat().st_mtime, value)
        return value


def list_configs() -> list[dict]:
    items = []
    for name, meta in REGISTRY.items():
        path = _seed_if_missing(name)
        items.append({
            "name": name,
            "title": meta["title"],
            "description": meta["description"],
            "path": str(path),
            "updated_at": path.stat().st_mtime,
        })
    return items
