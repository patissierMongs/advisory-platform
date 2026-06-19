"""내부 게시판 — 사내 누구나(무인증) 보안권고문을 게시글처럼 보고 댓글로 회신.

설계
  · 그룹웨어 의존 없이 이 시스템 자체가 게시판이 된다(폐쇄망 내부 공유).
  · 인증 없음 — 부서(드롭다운/직접입력) + 이름만으로 댓글. 관리자 작성은 is_admin 표식.
  · 댓글에 조치상태(ack_status)를 첨부하면, 해당 (권고문, 부서) 발송 ack 로 동기화(둘 다).
  · 노출 범위: 관리자가 '게시판 게시'한(board_published_at 설정) 권고문만 게시판에 보인다.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import enums, serializers
from ..audit import record
from ..db import get_db
from ..models import Advisory, AdvisoryComment, Asset, Department, Match, Notification
from ..schemas import CommentIn

router = APIRouter(prefix="/api/v1/board", tags=["board"])


def _published(db: Session, advisory_id: int) -> Advisory:
    adv = db.get(Advisory, advisory_id)
    if not adv or adv.board_published_at is None:
        raise HTTPException(404, "게시판에 공개된 권고문이 아닙니다")
    return adv


@router.get("/departments")
def board_departments(db: Session = Depends(get_db)):
    """댓글 부서 선택용(검색 드롭다운) — 활성 부서 목록."""
    rows = db.scalars(
        select(Department).where(Department.is_active.is_(True)).order_by(Department.name)
    ).all()
    return {"items": [{"id": d.id, "name": d.name} for d in rows]}


def _dept_ack_map(db: Session, department_id: int) -> dict[int, "enums.AckStatus"]:
    """부서별 (권고문 → 최신 발송 ack 상태) 맵. id 오름차순이라 마지막이 최신."""
    out: dict[int, enums.AckStatus] = {}
    for n in db.scalars(
        select(Notification)
        .where(Notification.department_id == department_id)
        .order_by(Notification.id)
    ).all():
        out[n.advisory_id] = n.ack_status
    return out


def _relevant_advisory_ids(db: Session, department_id: int) -> set[int]:
    """해당 부서가 대상인 권고문 = 발송 내역 OR 자산 매칭이 있는 권고문."""
    notif = set(db.scalars(
        select(Notification.advisory_id).where(Notification.department_id == department_id)
    ).all())
    matched = set(db.scalars(
        select(Match.advisory_id)
        .join(Asset, Match.asset_id == Asset.id)
        .where(Asset.department_id == department_id, Match.status == enums.MatchStatus.MATCHED)
    ).all())
    return notif | matched


def _matches_query(a: Advisory, ql: str) -> bool:
    """자유 검색 — 제목·문서번호·출처, 그리고 매칭된 자산의 자산번호·담당자·부서명."""
    for v in (a.title, a.doc_no, a.source_org):
        if v and ql in v.lower():
            return True
    for m in a.matches:
        if m.status != enums.MatchStatus.MATCHED or m.asset is None:
            continue
        asset = m.asset
        if asset.asset_no and ql in asset.asset_no.lower():
            return True
        if asset.owner_name and ql in asset.owner_name.lower():
            return True
        if asset.department is not None and ql in asset.department.name.lower():
            return True
    return False


@router.get("/advisories")
def board_list(
    q: str | None = None,
    department_id: int | None = None,
    exclude_done: bool = True,
    db: Session = Depends(get_db),
):
    """게시판 목록 — 공개된 권고문을 최근 게시순으로. 댓글 수 포함.

    필터(선택):
      · q — 자유 검색: 자산번호·담당자명·부서명·제목·문서번호 부분일치.
      · department_id — 해당 부서 대상 권고문만(발송 OR 자산 매칭).
      · exclude_done — 완료 제외(기본 True). 부서 지정 시 그 부서가 '조치완료'한 건 제외,
        미지정 시 권고문 상태가 COMPLETED 인 건 제외.
    """
    advs = db.scalars(
        select(Advisory)
        .where(Advisory.board_published_at.is_not(None))
        .order_by(Advisory.board_published_at.desc())
    ).all()

    dept_ack: dict[int, enums.AckStatus] = {}
    if department_id is not None:
        relevant = _relevant_advisory_ids(db, department_id)
        advs = [a for a in advs if a.id in relevant]
        dept_ack = _dept_ack_map(db, department_id)
        if exclude_done:
            advs = [a for a in advs if dept_ack.get(a.id) != enums.AckStatus.DONE]
    elif exclude_done:
        advs = [a for a in advs if a.status != enums.AdvisoryStatus.COMPLETED]

    if q and q.strip():
        ql = q.strip().lower()
        advs = [a for a in advs if _matches_query(a, ql)]

    counts = dict(
        db.execute(
            select(AdvisoryComment.advisory_id, func.count(AdvisoryComment.id))
            .group_by(AdvisoryComment.advisory_id)
        ).all()
    )
    items = []
    for a in advs:
        item = serializers.board_advisory_item(a, comment_count=counts.get(a.id, 0))
        if department_id is not None:
            ack = dept_ack.get(a.id)
            item["dept_ack_status"] = ack.value if ack else None
            item["dept_ack_status_ko"] = enums.ACK_KO.get(ack) if ack else None
        items.append(item)
    return {"items": items, "q": q, "department_id": department_id, "exclude_done": exclude_done}


@router.get("/advisories/{advisory_id}/file")
def board_file(advisory_id: int, db: Session = Depends(get_db)):
    """게시판 공개 권고문의 원본 PDF 열람(inline). 공개 안 된 건 404."""
    import os

    adv = _published(db, advisory_id)
    if not adv.file_path or not os.path.exists(adv.file_path):
        raise HTTPException(404, "원본 PDF 파일이 없습니다")
    return FileResponse(adv.file_path, media_type="application/pdf",
                        headers={"Content-Disposition": "inline"})


@router.get("/advisories/{advisory_id}")
def board_detail(advisory_id: int, db: Session = Depends(get_db)):
    """게시판 상세 — 권고문 요약 + 영향 CVE 요약 + 댓글 스레드."""
    adv = _published(db, advisory_id)
    cves = [
        {
            "cve_id_text": ac.cve_id_text,
            "lookup_status": ac.lookup_status.value,
            "product_name": ac.cve.product_name if ac.cve else None,
            "severity": ac.cve.severity.value if ac.cve else None,
        }
        for ac in adv.cves
    ]
    matches = [serializers.match_item(m) for m in adv.matches
               if m.status == enums.MatchStatus.MATCHED]
    return {
        "advisory": serializers.board_advisory_item(adv, comment_count=len(adv.comments)),
        "cves": cves,
        "matches": matches,
        "comments": [serializers.comment_item(c) for c in adv.comments],
    }


@router.get("/advisories/{advisory_id}/comments")
def board_comments(advisory_id: int, db: Session = Depends(get_db)):
    adv = _published(db, advisory_id)
    return {"items": [serializers.comment_item(c) for c in adv.comments]}


@router.post("/advisories/{advisory_id}/comments", status_code=201)
def add_comment(advisory_id: int, body: CommentIn, request: Request, db: Session = Depends(get_db)):
    """댓글 작성(무인증). ack_status 첨부 시 해당 부서 발송 ack 로 동기화."""
    adv = _published(db, advisory_id)

    dept = None
    dept_name = (body.department_name or "").strip() or None
    if body.department_id is not None:
        dept = db.get(Department, body.department_id)
        if not dept:
            raise HTTPException(404, "부서 없음")
        dept_name = dept.name

    comment = AdvisoryComment(
        advisory_id=adv.id,
        author_name=body.author_name.strip(),
        author_department_id=dept.id if dept else None,
        author_department_name=dept_name,
        body=body.body.strip(),
        ack_status=body.ack_status,
        is_admin=bool(body.is_admin),
    )
    db.add(comment)

    # 조치상태 첨부 + 부서 식별 가능 → (이 권고문, 부서)의 가장 최근 발송 ack 동기화.
    ack_synced = None
    if body.ack_status is not None and dept is not None:
        n = db.scalar(
            select(Notification)
            .where(Notification.advisory_id == adv.id, Notification.department_id == dept.id)
            .order_by(Notification.id.desc())
        )
        if n is not None:
            n.ack_status = body.ack_status
            n.ack_note = comment.body
            n.ack_by = comment.author_name
            n.ack_updated_at = datetime.now(timezone.utc)
            if body.ack_status == enums.AckStatus.DONE:
                n.status = enums.NotificationStatus.ACKED
            ack_synced = n.id

    record(db, action="BOARD_COMMENT", actor_id=None, entity_type="advisory",
           entity_id=adv.id, detail={"author": comment.author_name, "dept": dept_name,
                                     "ack": body.ack_status.value if body.ack_status else None,
                                     "ack_synced_notification": ack_synced}, request=request)
    db.commit()
    db.refresh(comment)
    return {"comment": serializers.comment_item(comment), "ack_synced_notification": ack_synced}


@router.delete("/comments/{comment_id}", status_code=204)
def delete_comment(comment_id: int, request: Request, db: Session = Depends(get_db)):
    """댓글 삭제(관리자 모더레이션). 무인증 환경이라 관리자 화면에서만 호출."""
    c = db.get(AdvisoryComment, comment_id)
    if not c:
        raise HTTPException(404, "댓글 없음")
    advisory_id = c.advisory_id
    db.delete(c)
    record(db, action="BOARD_COMMENT_DELETE", actor_id=None, entity_type="advisory",
           entity_id=advisory_id, detail={"comment_id": comment_id}, request=request)
    db.commit()
    return None
