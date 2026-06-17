"""CVE 피드 파싱·적재 (명세서 §4.4).

형식 자동 판별: NVD JSON(vulnerabilities[].cve) / 일반·KISA CSV / 내부 표준 JSON.
검증 단계에서 정규화 레코드를 산출하고, 적용 단계에서 cve 테이블에 upsert 한다.
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import re
from collections.abc import Iterator
from datetime import date, datetime

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as _pg_insert
from sqlalchemy.dialects.sqlite import insert as _sqlite_insert
from sqlalchemy.orm import Session

from .. import enums
from ..models import Cve
from .extract import CVE_RE
from .normalize import normalize_product

REQUIRED = ("cve_id",)  # 최소 필수: 코드. product/versions/severity 는 보완 가능.

# SQLite 바인드 변수 한도(구버전 999) 회피용 IN 절 청크 크기.
_IN_CHUNK = 900


def _existing_ids(db: Session, ids: list[str]) -> set[str]:
    """주어진 cve_id 중 DB에 이미 있는 것만 반환. IN 절을 청크로 분할."""
    have: set[str] = set()
    for i in range(0, len(ids), _IN_CHUNK):
        chunk = ids[i : i + _IN_CHUNK]
        have.update(db.scalars(select(Cve.cve_id).where(Cve.cve_id.in_(chunk))))
    return have


def _parse_date(v) -> date | None:
    if not v:
        return None
    s = str(v)[:10]
    for fmt in ("%Y-%m-%d", "%Y.%m.%d", "%Y/%m/%d"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def _sev_from_any(severity_text, cvss) -> enums.Severity:
    if severity_text:
        st = str(severity_text).strip()
        if st in enums.KO_TO_SEVERITY:
            return enums.KO_TO_SEVERITY[st]
        up = st.upper()
        if up in enums.Severity.__members__:
            return enums.Severity[up]
    try:
        return enums.severity_from_cvss(float(cvss)) if cvss not in (None, "") else enums.Severity.MEDIUM
    except (TypeError, ValueError):
        return enums.Severity.MEDIUM


def _norm_record(raw: dict) -> dict | None:
    code_match = CVE_RE.search(str(raw.get("cve_id") or raw.get("id") or "").replace(" ", "-"))
    if not code_match:
        return None
    cve_id = code_match.group(0).upper()
    product_name = raw.get("product_name") or raw.get("product") or raw.get("matchKey") or None
    product_key = raw.get("product_key") or (normalize_product(product_name) if product_name else None)

    versions = raw.get("affected_versions")
    if versions is None:
        versions = raw.get("versions")
    if isinstance(versions, str):
        versions = [v.strip() for v in re.split(r"[;,/]", versions) if v.strip()] or "*"

    return {
        "cve_id": cve_id,
        "product_name": product_name,
        "product_key": product_key,
        "affected_versions": versions if versions not in (None, []) else "*",
        "cpe_list": raw.get("cpe_list") or raw.get("cpe") or None,
        "severity": _sev_from_any(raw.get("severity"), raw.get("cvss_score") or raw.get("cvss")),
        "cvss_score": raw.get("cvss_score") or raw.get("cvss") or None,
        "description": raw.get("description") or raw.get("desc") or None,
        "published_at": _parse_date(raw.get("published_at") or raw.get("published")),
        "source": raw.get("source") or None,
    }


def _norm_nvd_item(item: dict) -> dict | None:
    """NVD vulnerabilities[] 원소 하나 → 정규화 레코드(없으면 None)."""
    cve = item.get("cve", {})
    cve_id = cve.get("id")
    if not cve_id:
        return None
    # 설명(영문 우선, 없으면 첫 항목)
    descs = cve.get("descriptions", [])
    desc = next((d["value"] for d in descs if d.get("lang") == "en"), None) or (
        descs[0]["value"] if descs else None
    )
    # CVSS (v3.1 → v3.0 → v2)
    metrics = cve.get("metrics", {})
    mlist = (
        metrics.get("cvssMetricV31")
        or metrics.get("cvssMetricV30")
        or metrics.get("cvssMetricV2")
        or []
    )
    cvss = base_sev = None
    if mlist:
        cdata = mlist[0].get("cvssData", {})
        cvss = cdata.get("baseScore")
        base_sev = mlist[0].get("baseSeverity") or cdata.get("baseSeverity")
    # CPE → 제품명/영향버전(첫 cpeMatch 기준의 근사 추출, 정밀화는 §9 결정항목)
    product_name = None
    affected = "*"
    cpe_list = []
    for node in (_iter_cpe(cve)):
        cpe_list.append(node.get("criteria"))
        if product_name is None:
            product_name = _product_from_cpe(node.get("criteria"))
        rule = _versionrule_from_cpe(node)
        if rule is not None:
            affected = rule
    return _norm_record(
        {
            "cve_id": cve_id,
            "product_name": product_name,
            "affected_versions": affected,
            "cpe_list": [c for c in cpe_list if c] or None,
            "severity": base_sev,
            "cvss_score": cvss,
            "description": desc,
            "published": cve.get("published"),
            "source": "NVD",
        }
    )


def _parse_nvd(doc: dict) -> list[dict]:
    return [r for r in (_norm_nvd_item(it) for it in doc.get("vulnerabilities", [])) if r]


def _iter_cpe(cve: dict):
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if m.get("vulnerable"):
                    yield m


def _product_from_cpe(criteria: str | None) -> str | None:
    # cpe:2.3:a:microsoft:office:...  → "microsoft office"
    if not criteria:
        return None
    parts = criteria.split(":")
    if len(parts) >= 5:
        vendor, product = parts[3], parts[4]
        return f"{vendor} {product}".replace("_", " ").strip()
    return None


def _versionrule_from_cpe(m: dict):
    if m.get("versionEndExcluding"):
        return {"lt": m["versionEndExcluding"]}
    if m.get("versionStartIncluding") and m.get("versionEndIncluding"):
        return {"range": [m["versionStartIncluding"], m["versionEndIncluding"]]}
    return None


# CSV 헤더 별칭 정규화 표(배치·스트리밍 공유).
_CSV_ALIAS = {
    "cve": "cve_id", "cve_id": "cve_id", "cveid": "cve_id",
    "product": "product", "제품": "product", "제품명": "product", "os": "product",
    "versions": "versions", "version": "versions", "버전": "versions", "영향버전": "versions",
    "severity": "severity", "심각도": "severity", "등급": "severity",
    "cvss": "cvss", "cvss_score": "cvss", "점수": "cvss",
    "description": "description", "desc": "description", "설명": "description",
    "published": "published", "게시일": "published", "발표일": "published",
    "source": "source", "출처": "source",
}


def _parse_csv(text: str) -> list[dict]:
    return list(_iter_csv(io.StringIO(text)))


def _iter_csv(fileobj) -> Iterator[dict]:
    """CSV 파일객체를 한 행씩 스트리밍 정규화."""
    for row in csv.DictReader(fileobj):
        norm = {}
        for k, v in row.items():
            if k is None:
                continue
            key = _CSV_ALIAS.get(k.strip().lower())
            if key:
                norm[key] = v
        rec = _norm_record(norm)
        if rec:
            yield rec


def parse_feed(filename: str, content: bytes) -> list[dict]:
    """피드 파일 → 정규화 레코드 목록. 형식 자동 판별."""
    name = (filename or "").lower()
    text = content.decode("utf-8-sig", errors="replace")
    stripped = text.lstrip()
    if name.endswith(".csv") or (stripped and stripped[0] not in "{["):
        return _parse_csv(text)
    # JSON
    doc = json.loads(text)
    if isinstance(doc, dict) and "vulnerabilities" in doc:
        return _parse_nvd(doc)
    items = doc.get("cves") if isinstance(doc, dict) else doc
    if not isinstance(items, list):
        raise ValueError("지원하지 않는 피드 형식")
    return [r for r in (_norm_record(x) for x in items) if r]


# ── 대용량 스트리밍 적재 (저메모리 환경) ─────────────────────────────────
# 1.6GB급 NVD JSON 을 통째로 json.loads 하면 객체 그래프가 수 GB → OOM.
# 파일을 청크로 읽어 배열 원소만 raw_decode(검증된 stdlib 디코더)로 하나씩
# 꺼내 정규화 → 상수 메모리. 프레이밍(배열 시작·구분자)만 직접 처리한다.

_STREAM_CHUNK = 1 << 18  # 256KB


def _iter_json_array(fileobj, array_key: str | None) -> Iterator[dict]:
    """텍스트 파일객체에서 배열 원소(객체)를 하나씩 yield.

    array_key 가 주어지면 해당 키의 배열을, None 이면 최상위 배열을 읽는다.
    """
    dec = json.JSONDecoder()
    buf = ""
    pos = 0
    eof = False

    def fill() -> bool:
        nonlocal buf, pos, eof
        chunk = fileobj.read(_STREAM_CHUNK)
        if not chunk:
            eof = True
            return False
        if pos:  # 소비한 접두부 폐기 → 버퍼를 청크 크기로 유지
            buf = buf[pos:]
            pos = 0
        buf += chunk
        return True

    # 1) 배열 시작 '[' 직후로 위치 이동
    if array_key is not None:
        needle = '"' + array_key + '"'
        while needle not in buf:
            if not fill():
                return  # 키 없음
        search_from = buf.index(needle) + len(needle)
    else:
        search_from = 0
    while True:
        b = buf.find("[", search_from)
        if b != -1:
            pos = b + 1
            break
        if not fill():
            return

    # 2) 원소 반복: 공백/콤마 건너뛰고 raw_decode
    while True:
        while True:
            while pos < len(buf) and buf[pos] in " \t\r\n,":
                pos += 1
            if pos < len(buf):
                break
            if not fill():
                return
        if buf[pos] == "]":
            return  # 배열 끝
        while True:
            try:
                obj, end = dec.raw_decode(buf, pos)
                break
            except json.JSONDecodeError:
                if not fill():  # 원소가 청크 경계에 걸림 → 더 읽고 재시도
                    raise
        pos = end
        yield obj


def _open_text(path: str, newline: str | None = None):
    """텍스트 스트림 반환. gzip(매직 1f 8b)이면 투명하게 해제 — NVD .json.gz 직접 처리."""
    with open(path, "rb") as f:
        gzipped = f.read(2) == b"\x1f\x8b"
    opener = gzip.open if gzipped else open
    return opener(path, "rt", encoding="utf-8-sig", errors="replace", newline=newline)


def _peek(path: str, n: int = 1 << 20) -> str:
    with _open_text(path) as f:
        return f.read(n)


def iter_records_from_path(path: str, filename: str | None) -> Iterator[dict]:
    """피드 파일 경로 → 정규화 레코드 스트림(상수 메모리). 형식 자동 판별(.gz 포함)."""
    name = (filename or "").lower()
    head = _peek(path)
    stripped = head.lstrip()
    if name.endswith((".csv", ".csv.gz")) or (stripped and stripped[0] not in "{["):
        with _open_text(path, newline="") as f:
            yield from _iter_csv(f)
        return
    # JSON: 배열 위치·원소 정규화 방식 결정
    if stripped[:1] == "[":
        key, is_nvd = None, False
    elif '"vulnerabilities"' in head:
        key, is_nvd = "vulnerabilities", True
    elif '"cves"' in head:
        key, is_nvd = "cves", False
    else:
        raise ValueError("지원하지 않는 피드 형식")
    with _open_text(path) as f:
        for item in _iter_json_array(f, key):
            rec = _norm_nvd_item(item) if is_nvd else _norm_record(item)
            if rec:
                yield rec


def count_new_updated(db: Session, records: Iterator[dict]) -> tuple[int, int, str | None]:
    """스트림을 소비하며 신규/갱신 건수와 첫 레코드의 source 산출(DB 미반영)."""
    added = updated = 0
    first_source = None
    batch: list[str] = []

    def flush() -> None:
        nonlocal added, updated
        if not batch:
            return
        have = _existing_ids(db, batch)
        for cid in batch:
            if cid in have:
                updated += 1
            else:
                added += 1
        batch.clear()

    for r in records:
        if first_source is None:
            first_source = r.get("source")
        batch.append(r["cve_id"])
        if len(batch) >= _IN_CHUNK:
            flush()
    flush()
    return added, updated, first_source


def apply_stream(db: Session, records: Iterator[dict], feed_import_id: int | None,
                 batch_size: int = 1000) -> tuple[int, int]:
    """레코드 스트림을 batch_size 단위로 upsert·커밋. 반환 (added, updated).

    upsert 는 cve_id 기준 멱등 → 중단 후 재적용 안전. 벌크 upsert(ORM 객체 미생성)라 상수 메모리.
    """
    added = updated = 0
    batch: list[dict] = []

    def flush() -> None:
        nonlocal added, updated
        if not batch:
            return
        a, u = apply_records(db, batch, feed_import_id)
        added += a
        updated += u
        db.commit()
        batch.clear()

    for r in records:
        batch.append(r)
        if len(batch) >= batch_size:
            flush()
    flush()
    return added, updated


# cve 테이블 upsert 시 충돌(cve_id 중복) 행에서 갱신할 데이터 컬럼.
_UPSERT_COLS = ("product_name", "product_key", "affected_versions", "cpe_list",
                "severity", "cvss_score", "description", "published_at", "source",
                "feed_import_id")
# 한 INSERT 문의 바인드 변수 한계 회피용 행수 상한.
# SQLite≥3.32(2020) 32766 / PostgreSQL 65535 내. (cve_id 포함 컬럼수 기준)
_UPSERT_ROWS = max(1, 20000 // (len(_UPSERT_COLS) + 1))


def _dialect_insert(db: Session):
    return _pg_insert if db.bind.dialect.name == "postgresql" else _sqlite_insert


def apply_records(db: Session, records: list[dict], feed_import_id: int | None) -> tuple[int, int]:
    """cve 테이블 벌크 upsert (키: cve_id). 반환 (added, updated).

    ORM 객체 대신 INSERT … ON CONFLICT DO UPDATE 로 일괄 처리 → 대량 적재 고속·저메모리.
    """
    if not records:
        return 0, 0
    # 한 문장에서 동일 cve_id 를 두 번 건드리지 못하므로 배치 내 중복 제거(나중 값 우선).
    by_id: dict[str, dict] = {r["cve_id"]: r for r in records}
    ids = list(by_id)
    have = _existing_ids(db, ids)
    added = sum(1 for cid in ids if cid not in have)

    rows = [{c: r.get(c) for c in _UPSERT_COLS} | {"cve_id": cid, "feed_import_id": feed_import_id}
            for cid, r in by_id.items()]
    ins = _dialect_insert(db)
    for i in range(0, len(rows), _UPSERT_ROWS):
        stmt = ins(Cve).values(rows[i : i + _UPSERT_ROWS])
        set_ = {c: getattr(stmt.excluded, c) for c in _UPSERT_COLS}
        set_["updated_at"] = func.now()  # Core upsert 는 onupdate 미발동 → 명시
        db.execute(stmt.on_conflict_do_update(index_elements=["cve_id"], set_=set_))
    return added, len(ids) - added
