"""CVE 피드 파싱·적재 (명세서 §4.4).

형식 자동 판별: NVD JSON(vulnerabilities[].cve) / 일반·KISA CSV / 내부 표준 JSON.
검증 단계에서 정규화 레코드를 산출하고, 적용 단계에서 cve 테이블에 upsert 한다.
"""
from __future__ import annotations

import csv
import io
import json
import re
from datetime import date, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import enums
from ..models import Cve
from .extract import CVE_RE
from .normalize import normalize_product

REQUIRED = ("cve_id",)  # 최소 필수: 코드. product/versions/severity 는 보완 가능.


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


def _parse_nvd(doc: dict) -> list[dict]:
    out = []
    for item in doc.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
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
        out.append(
            _norm_record(
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
        )
    return [r for r in out if r]


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


def _parse_csv(text: str) -> list[dict]:
    # 헤더 별칭 정규화.
    alias = {
        "cve": "cve_id", "cve_id": "cve_id", "cveid": "cve_id",
        "product": "product", "제품": "product", "제품명": "product", "os": "product",
        "versions": "versions", "version": "versions", "버전": "versions", "영향버전": "versions",
        "severity": "severity", "심각도": "severity", "등급": "severity",
        "cvss": "cvss", "cvss_score": "cvss", "점수": "cvss",
        "description": "description", "desc": "description", "설명": "description",
        "published": "published", "게시일": "published", "발표일": "published",
        "source": "source", "출처": "source",
    }
    reader = csv.DictReader(io.StringIO(text))
    out = []
    for row in reader:
        norm = {}
        for k, v in row.items():
            if k is None:
                continue
            key = alias.get(k.strip().lower())
            if key:
                norm[key] = v
        rec = _norm_record(norm)
        if rec:
            out.append(rec)
    return out


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


def apply_records(db: Session, records: list[dict], feed_import_id: int | None) -> tuple[int, int]:
    """cve 테이블 upsert (키: cve_id). 반환 (added, updated)."""
    added = updated = 0
    existing = {c.cve_id: c for c in db.scalars(select(Cve).where(Cve.cve_id.in_([r["cve_id"] for r in records])))} if records else {}
    for r in records:
        c = existing.get(r["cve_id"])
        if c is None:
            c = Cve(cve_id=r["cve_id"])
            db.add(c)
            existing[r["cve_id"]] = c
            added += 1
        else:
            updated += 1
        c.product_name = r["product_name"]
        c.product_key = r["product_key"]
        c.affected_versions = r["affected_versions"]
        c.cpe_list = r["cpe_list"]
        c.severity = r["severity"]
        c.cvss_score = r["cvss_score"]
        c.description = r["description"]
        c.published_at = r["published_at"]
        c.source = r["source"]
        c.feed_import_id = feed_import_id
    db.flush()
    return added, updated


def validate_counts(db: Session, records: list[dict]) -> tuple[int, int]:
    """적용 전 신규/갱신 건수 계산(DB 미반영)."""
    if not records:
        return 0, 0
    ids = [r["cve_id"] for r in records]
    have = set(db.scalars(select(Cve.cve_id).where(Cve.cve_id.in_(ids))))
    added = sum(1 for r in records if r["cve_id"] not in have)
    return added, len(records) - added
