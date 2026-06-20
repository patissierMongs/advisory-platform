"""모델 → 응답 dict 직렬화. 프론트는 이 도메인 데이터를 받아 표현(스타일)을 계산한다."""
from __future__ import annotations

from datetime import date, datetime

from . import enums
from .models import (
    Advisory, AdvisoryComment, AdvisoryCve, Asset, Cve, Match, MessageTemplate, Notification,
)

_SEV_RANK = {
    enums.Severity.CRITICAL: 4,
    enums.Severity.HIGH: 3,
    enums.Severity.MEDIUM: 2,
    enums.Severity.LOW: 1,
}


def _d(v: date | datetime | None) -> str | None:
    if v is None:
        return None
    if isinstance(v, datetime):
        return v.isoformat()
    return v.isoformat()


def cve_item(c: Cve) -> dict:
    return {
        "id": c.id,
        "cve_id": c.cve_id,
        "product_name": c.product_name,
        "product_key": c.product_key,
        "affected_versions": c.affected_versions,
        "severity": c.severity.value,
        "cvss_score": float(c.cvss_score) if c.cvss_score is not None else None,
        "description": c.description,
        "published_at": _d(c.published_at),
        "source": c.source,
    }


def advisory_brief(a: Advisory, *, match_count: int | None = None) -> dict:
    found = sum(1 for ac in a.cves if ac.lookup_status == enums.LookupStatus.FOUND)
    not_found = len(a.cves) - found
    d_day = None
    if a.due_at:
        d_day = (a.due_at - date.today()).days
    if a.status in (enums.AdvisoryStatus.COMPLETED, enums.AdvisoryStatus.ARCHIVED):
        sla = enums.SlaStatus.DONE.value
    elif d_day is None:
        sla = enums.SlaStatus.NORMAL.value
    elif d_day < 0:
        sla = enums.SlaStatus.OVERDUE.value
    elif d_day <= 3:
        sla = enums.SlaStatus.IMMINENT.value
    else:
        sla = enums.SlaStatus.NORMAL.value
    return {
        "id": a.id,
        "doc_no": a.doc_no,
        "title": a.title,
        "source_org": a.source_org,
        "receive_channel": a.receive_channel.value if a.receive_channel else None,
        "received_at": _d(a.received_at),
        "due_at": _d(a.due_at),
        "d_day": d_day,
        "sla_status": sla,
        "page_count": a.page_count,
        "status": a.status.value,
        "extract_phase": a.extract_phase,
        "error_message": a.error_message,
        "extracted": len(a.cves),
        "found": found,
        "not_found": not_found,
        "match_count": match_count,
        "board_post_id": a.board_post_id,
        "board_published": a.board_published_at is not None,
        "board_published_at": _d(a.board_published_at),
    }


def _max_severity(a: Advisory) -> str | None:
    sevs = [ac.cve.severity for ac in a.cves if ac.cve]
    if not sevs:
        return None
    top = max(sevs, key=lambda s: _SEV_RANK.get(s, 0))
    return top.value


def _impact(a: Advisory) -> dict:
    """권고문의 영향 집계 — 매칭(MATCHED)된 자산 기준 부서·담당자·제품."""
    return impact_from_matches(a.matches)


def impact_from_matches(matches) -> dict:
    """주어진 매칭 리스트로 영향 집계(부서·담당자·제품). 게시판 필터 스코핑 시 재사용."""
    depts: dict[int, dict] = {}
    products: dict[str, int] = {}
    asset_total = 0
    for m in matches:
        if m.status != enums.MatchStatus.MATCHED:
            continue
        asset = m.asset
        if asset is None:
            continue
        asset_total += 1
        d = asset.department
        if d is not None:
            e = depts.setdefault(d.id, {"id": d.id, "name": d.name, "asset_ids": set(), "owners": set()})
            e["asset_ids"].add(asset.id)
            if asset.owner_name:
                e["owners"].add(asset.owner_name)
        prod = asset.product_raw or asset.product_key
        if prod:
            products[prod] = products.get(prod, 0) + 1
    dept_list = sorted(
        ({"id": e["id"], "name": e["name"], "asset_count": len(e["asset_ids"]),
          "owners": sorted(e["owners"])} for e in depts.values()),
        key=lambda x: x["name"],
    )
    return {
        "affected_departments": dept_list,
        "affected_dept_count": len(dept_list),
        "affected_products": sorted(products.keys()),
        "affected_asset_count": asset_total,
    }


def board_advisory_item(a: Advisory, *, comment_count: int | None = None) -> dict:
    """내부 게시판 목록/상세용 요약 — 사내 누구나 보는 공개 뷰."""
    brief = advisory_brief(a)
    brief["max_severity"] = _max_severity(a)
    brief["max_severity_ko"] = (
        enums.SEVERITY_KO.get(enums.Severity(brief["max_severity"]))
        if brief["max_severity"] else None
    )
    brief["comment_count"] = comment_count if comment_count is not None else len(a.comments)
    brief.update(_impact(a))
    return brief


def comment_item(c: AdvisoryComment) -> dict:
    return {
        "id": c.id,
        "advisory_id": c.advisory_id,
        "author_name": c.author_name,
        "department_id": c.author_department_id,
        "department": c.author_department_name or (c.department.name if c.department else None),
        "body": c.body,
        "ack_status": c.ack_status.value if c.ack_status else None,
        "ack_status_ko": enums.ACK_KO.get(c.ack_status) if c.ack_status else None,
        "is_admin": c.is_admin,
        "evidence": c.evidence_name,
        "has_evidence": c.evidence_path is not None,
        "created_at": _d(c.created_at),
    }


def message_template_item(t: MessageTemplate) -> dict:
    return {
        "id": t.id,
        "title": t.title,
        "body": t.body,
        "created_at": _d(t.created_at),
    }


def advisory_cve_item(ac: AdvisoryCve, *, match_count: int = 0) -> dict:
    c = ac.cve
    return {
        "id": ac.id,
        "cve_id_text": ac.cve_id_text,
        "lookup_status": ac.lookup_status.value,
        "product_name": c.product_name if c else None,
        "product_key": c.product_key if c else None,
        "affected_versions": c.affected_versions if c else None,
        "severity": c.severity.value if c else None,
        "description": c.description if c else None,
        "published_at": _d(c.published_at) if c else None,
        "source": c.source if c else None,
        "is_new": False,
        "match_count": match_count,
        "source_snippet": ac.source_snippet,
    }


def asset_item(a: Asset, *, dept_name: str | None = None) -> dict:
    return {
        "id": a.id,
        "asset_no": a.asset_no,
        "department_id": a.department_id,
        "department": dept_name,
        "product_raw": a.product_raw,
        "product_key": a.product_key,
        "version_raw": a.version_raw,
        "version_norm": a.version_norm,
        "ip": a.ip,
        "owner_name": a.owner_name,
        "owner_team": a.owner_team,
        "owner_contact": a.owner_contact,
        "status": a.status.value,
    }


def match_item(m: Match) -> dict:
    a = m.asset
    ac = m.advisory_cve
    c = ac.cve
    return {
        "id": m.id,
        "cve": ac.cve_id_text,
        "asset_id": a.id,
        "asset_no": a.asset_no,
        "ip": a.ip,
        "department_id": a.department_id,
        "department": a.department.name if a.department else None,
        "owner_name": a.owner_name,
        "owner_team": a.owner_team,
        "owner_contact": a.owner_contact,
        "product": a.product_raw or a.product_key,
        "version": a.version_raw or a.version_norm,
        "product_ver": f"{a.product_raw or a.product_key} · {a.version_raw or a.version_norm or ''}".strip(" ·"),
        "severity": c.severity.value if c else None,
        "status": m.status.value,
        "candidate": bool(m.match_reason and m.match_reason.get("candidate")),
        "suggested_exclude": bool(m.match_reason and m.match_reason.get("suggested_exclude")),
        "excluded_reason": m.excluded_reason,
        # 자산별 조치 회신(게시판 담당자 처리). 미처리는 NONE.
        "ack_status": m.ack_status.value if m.ack_status else "NONE",
        "ack_status_ko": enums.ACK_KO.get(m.ack_status, "미회신") if m.ack_status else "미회신",
        "ack_by": m.ack_by,
        "ack_at": _d(m.ack_at),
    }


def notification_item(n: Notification) -> dict:
    return {
        "id": n.id,
        "advisory_id": n.advisory_id,
        "department_id": n.department_id,
        "department": n.department.name if n.department else None,
        "channels": n.channels,
        "message_body": n.message_body,
        "asset_count": len(n.asset_ids or []),
        "status": n.status.value,
        "ack_status": n.ack_status.value,
        "ack_status_ko": enums.ACK_KO.get(n.ack_status, n.ack_status.value),
        "ack_note": n.ack_note,
        "ack_by": n.ack_by,
        "ack_updated_at": _d(n.ack_updated_at),
        "evidence": n.ack_evidence_name,
        "reminded_at": _d(n.reminded_at),
        "reminder_count": n.reminder_count,
        "sent_at": _d(n.sent_at),
        "doc_no": n.advisory.doc_no if n.advisory else None,
    }


def scan_run_item(r) -> dict:
    return {
        "id": r.id,
        "label": r.label,
        "network": r.network,
        "source_name": r.source_name,
        "host_count": r.host_count,
        "open_port_count": r.open_port_count,
        "identified_count": r.identified_count,
        "unidentified_count": r.open_port_count - r.identified_count,
        "created_at": _d(r.created_at),
    }


def scan_port_item(p) -> dict:
    return {
        "id": p.id,
        "host": p.host,
        "hostname": p.hostname,
        "proto": p.proto,
        "port": p.port,
        "state": p.state,
        "reason": p.reason,
        "service": p.service,
        "product": p.product,
        "version": p.version,
        "extra": p.extra,
        "identified": p.identified,
        "evidence": p.evidence,
        "banner": p.banner,
        "note": p.note,
    }
