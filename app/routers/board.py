"""내부 게시판 — 사내 누구나(무인증) 보안권고문을 게시글처럼 보고 댓글로 회신.

설계
  · 그룹웨어 의존 없이 이 시스템 자체가 게시판이 된다(폐쇄망 내부 공유).
  · 인증 없음 — 부서(드롭다운/직접입력) + 이름만으로 댓글. 관리자 작성은 is_admin 표식.
  · 댓글에 조치상태(ack_status)를 첨부하면, 해당 (권고문, 부서) 발송 ack 로 동기화(둘 다).
  · 노출 범위: 관리자가 '게시판 게시'한(board_published_at 설정) 권고문만 게시판에 보인다.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import enums, serializers
from ..audit import record
from ..config import DATA_DIR, settings
from ..core.files import safe_filename
from ..db import get_db
from ..models import Advisory, AdvisoryComment, Asset, Department, Match, Notification
from ..schemas import AssetAckIn, CommentIn

router = APIRouter(prefix="/api/v1/board", tags=["board"])

EVIDENCE_DIR = DATA_DIR / "evidence"
EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


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


_ACK_KEY = {"NONE": "none", "IN_PROGRESS": "in_progress", "DONE": "done", "UNABLE": "unable"}


def _asset_counts(matches) -> dict:
    """매칭(자산) 리스트 → 자산 단위 조치 진행 집계. 게시판 진행률의 권위 소스."""
    counts = {"total": 0, "done": 0, "in_progress": 0, "unable": 0, "none": 0}
    for m in matches:
        counts["total"] += 1
        counts[_ACK_KEY[m.ack_status.value]] += 1
    counts["done_rate"] = round(counts["done"] / counts["total"] * 100) if counts["total"] else 0
    return counts


def _asset_progress_map(db: Session, advisory_ids: list[int]) -> dict[int, dict]:
    """게시글별 자산 단위 조치 진행현황 — 목록용 일괄 조회(MATCHED 자산 기준)."""
    if not advisory_ids:
        return {}
    rows = db.scalars(
        select(Match).where(Match.advisory_id.in_(advisory_ids),
                            Match.status == enums.MatchStatus.MATCHED)
    ).all()
    grouped: dict[int, list] = {}
    for m in rows:
        grouped.setdefault(m.advisory_id, []).append(m)
    return {aid: _asset_counts(ms) for aid, ms in grouped.items()}


def _asset_hit(m, ql: str) -> bool:
    """자유검색어가 이 매칭의 자산(번호·담당자·부서명) 중 하나라도 일치하는가."""
    a = m.asset
    if a is None:
        return False
    if a.asset_no and ql in a.asset_no.lower():
        return True
    if a.owner_name and ql in a.owner_name.lower():
        return True
    if a.department is not None and ql in a.department.name.lower():
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
    prog = _asset_progress_map(db, [a.id for a in advs])
    items = []
    for a in advs:
        item = serializers.board_advisory_item(a, comment_count=counts.get(a.id, 0))
        item["progress"] = prog.get(a.id)
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


def _public_comment(c) -> dict:
    """공개 게시판용 댓글 — 증빙 첨부는 노출하지 않는다(관리자 페이지에서만 열람)."""
    item = serializers.comment_item(c)
    item["evidence"] = None
    item["has_evidence"] = False
    return item


@router.get("/advisories/{advisory_id}")
def board_detail(advisory_id: int, q: str | None = None,
                 department_id: int | None = None, db: Session = Depends(get_db)):
    """게시판 상세 — 권고문 요약 + 영향 CVE + 자산별 조치 + 댓글 스레드.

    department_id(선택): '내 부서' 필터. 해당 부서의 자산·댓글만 남기고 타부서는 숨긴다
    (관리자 댓글은 항상 노출). 페이지 이동 후에도 유지되도록 화면이 매번 전달한다.
    q(선택): 게시판 검색어. 인물/부서/자산이 걸리면 본인 관련만, 제목/문서번호면 전체 노출.
    """
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
    matched = [m for m in adv.matches if m.status == enums.MatchStatus.MATCHED]

    # '내 부서' 필터 — 해당 부서 자산만.
    dept = db.get(Department, department_id) if department_id is not None else None
    if dept is not None:
        matched = [m for m in matched if m.asset and m.asset.department_id == dept.id]

    ql = q.strip().lower() if q and q.strip() else None
    title_hit = bool(ql and any(ql in (v or "").lower()
                                for v in (adv.title, adv.doc_no, adv.source_org)))
    q_scoped = False
    if ql and not title_hit:
        hits = [m for m in matched if _asset_hit(m, ql)]
        if hits:                       # 인물/부서/자산 검색 → 본인 관련만 노출
            matched = hits
            q_scoped = True

    def _visible(c):
        if dept is not None and not (
            c.is_admin or c.author_department_id == dept.id
            or (c.author_department_name and c.author_department_name == dept.name)
        ):
            return False
        if q_scoped and not (
            c.is_admin
            or (c.author_name and ql in c.author_name.lower())
            or (c.author_department_name and ql in c.author_department_name.lower())
        ):
            return False
        return True

    comments = [_public_comment(c) for c in adv.comments if _visible(c)]

    scoped = dept is not None or q_scoped
    advisory_item = serializers.board_advisory_item(adv, comment_count=len(comments))
    if scoped:   # 상단 영향 요약도 스코프(본인 부서)만 반영 — 타부서 노출 차단.
        advisory_item.update(serializers.impact_from_matches(matched))

    return {
        "advisory": advisory_item,
        "cves": cves,
        "matches": [serializers.match_item(m) for m in matched],
        "progress": _asset_counts(matched),
        "comments": comments,
        "scoped": scoped,
        "department_id": department_id,
        "q": q,
    }


@router.get("/advisories/{advisory_id}/comments")
def board_comments(advisory_id: int, db: Session = Depends(get_db)):
    adv = _published(db, advisory_id)
    return {"items": [_public_comment(c) for c in adv.comments]}


@router.post("/advisories/{advisory_id}/comments", status_code=201)
def add_comment(advisory_id: int, body: CommentIn, request: Request, db: Session = Depends(get_db)):
    """댓글 작성(무인증). ack_status 첨부 시 해당 부서 발송 ack 로 동기화.

    영향 자산 표에서 체크한 자산(match_ids)이 함께 오면, 그 자산들의 조치상태도 댓글로
    갱신한다(이름은 무관, 부서명만 일치하면 됨 — 다른 부서 자산이 섞이면 409 거부).
    """
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

    now = datetime.now(timezone.utc)
    ack_synced = None
    assets_updated = 0
    if body.ack_status is not None and dept is not None:
        # (1) 체크한 자산(match_ids)의 조치상태 갱신 — 부서 불일치 안전장치(이름은 무관).
        if body.match_ids:
            rows = db.scalars(
                select(Match).where(Match.id.in_(body.match_ids), Match.advisory_id == adv.id,
                                    Match.status == enums.MatchStatus.MATCHED)
            ).all()
            found = {m.id for m in rows}
            missing = [i for i in body.match_ids if i not in found]
            if missing:
                raise HTTPException(404, f"대상 자산을 찾을 수 없습니다(match {missing}).")
            mismatch = sorted({m.asset.asset_no or str(m.id) for m in rows
                               if m.asset.department_id != dept.id})
            if mismatch:
                raise HTTPException(409, detail={
                    "code": "DEPT_MISMATCH",
                    "message": (f"선택한 부서({dept_name})와 다른 부서의 자산이 포함되어 있습니다: "
                                f"{', '.join(mismatch)}. 본인 부서 자산만 선택하세요."),
                })
            for m in rows:
                m.ack_status = body.ack_status
                m.ack_by = comment.author_name
                m.ack_note = comment.body
                m.ack_at = now
            assets_updated = len(rows)

        # (2) (이 권고문, 부서)의 가장 최근 발송 ack 동기화.
        n = db.scalar(
            select(Notification)
            .where(Notification.advisory_id == adv.id, Notification.department_id == dept.id)
            .order_by(Notification.id.desc())
        )
        if n is not None:
            n.ack_status = body.ack_status
            n.ack_note = comment.body
            n.ack_by = comment.author_name
            n.ack_updated_at = now
            if body.ack_status == enums.AckStatus.DONE:
                n.status = enums.NotificationStatus.ACKED
            ack_synced = n.id

    record(db, action="BOARD_COMMENT", actor_id=None, entity_type="advisory",
           entity_id=adv.id, detail={"author": comment.author_name, "dept": dept_name,
                                     "ack": body.ack_status.value if body.ack_status else None,
                                     "assets_updated": assets_updated,
                                     "ack_synced_notification": ack_synced}, request=request)
    db.commit()
    db.refresh(comment)
    return {"comment": serializers.comment_item(comment), "ack_synced_notification": ack_synced,
            "assets_updated": assets_updated}


@router.post("/advisories/{advisory_id}/asset-ack")
def asset_ack(advisory_id: int, body: AssetAckIn, request: Request, db: Session = Depends(get_db)):
    """게시판 자산별 조치 회신(무인증) — 담당자가 본인 자산을 체크해 개별/일괄 처리.

    안전장치: 선택 부서(department_id)와 다른 부서의 자산이 섞이면 409(DEPT_MISMATCH)로 거부
    → 다른 부서 자산을 실수로 처리하는 것을 막는다. 부서 전체 자산이 DONE 이 되면 해당 부서
    최신 발송이력(Notification) ack 도 DONE 으로 동기화(관리자 발송이력과 일치 유지).
    """
    adv = _published(db, advisory_id)

    dept = None
    dept_name = (body.department_name or "").strip() or None
    if body.department_id is not None:
        dept = db.get(Department, body.department_id)
        if not dept:
            raise HTTPException(404, "부서 없음")
        dept_name = dept.name

    rows = db.scalars(
        select(Match).where(Match.id.in_(body.match_ids), Match.advisory_id == adv.id,
                            Match.status == enums.MatchStatus.MATCHED)
    ).all()
    found = {m.id for m in rows}
    missing = [i for i in body.match_ids if i not in found]
    if missing:
        raise HTTPException(404, f"대상 자산을 찾을 수 없습니다(match {missing}).")

    # 부서 불일치 방지 — 본인 부서 자산만 처리 가능.
    if dept is not None:
        mismatch = sorted({m.asset.asset_no or str(m.id) for m in rows
                           if m.asset.department_id != dept.id})
        if mismatch:
            raise HTTPException(409, detail={
                "code": "DEPT_MISMATCH",
                "message": (f"선택한 부서({dept_name})와 다른 부서의 자산이 포함되어 있습니다: "
                            f"{', '.join(mismatch)}. 본인 부서 자산만 선택하세요."),
            })

    now = datetime.now(timezone.utc)
    note = (body.note or "").strip() or None
    for m in rows:
        m.ack_status = body.ack_status
        m.ack_by = body.author_name.strip()
        m.ack_note = note
        m.ack_at = now

    # 발송이력 브리지 — 해당 부서 전체 자산이 DONE 이면 부서 발송 ack 도 DONE 동기화.
    synced = None
    if dept is not None:
        dept_matches = db.scalars(
            select(Match).join(Asset, Match.asset_id == Asset.id)
            .where(Match.advisory_id == adv.id, Match.status == enums.MatchStatus.MATCHED,
                   Asset.department_id == dept.id)
        ).all()
        if dept_matches and all(m.ack_status == enums.AckStatus.DONE for m in dept_matches):
            n = db.scalar(
                select(Notification)
                .where(Notification.advisory_id == adv.id, Notification.department_id == dept.id)
                .order_by(Notification.id.desc())
            )
            if n is not None:
                n.ack_status = enums.AckStatus.DONE
                n.status = enums.NotificationStatus.ACKED
                n.ack_by = body.author_name.strip()
                n.ack_updated_at = now
                synced = n.id

    record(db, action="BOARD_ASSET_ACK", actor_id=None, entity_type="advisory",
           entity_id=adv.id, detail={"author": body.author_name, "dept": dept_name,
                                     "ack": body.ack_status.value, "match_ids": sorted(found),
                                     "ack_synced_notification": synced}, request=request)
    db.commit()

    allm = db.scalars(
        select(Match).where(Match.advisory_id == adv.id,
                            Match.status == enums.MatchStatus.MATCHED)
    ).all()
    return {"updated": len(rows), "ack_synced_notification": synced,
            "progress": _asset_counts(allm)}


@router.post("/comments/{comment_id}/evidence", status_code=201)
async def upload_comment_evidence(comment_id: int, request: Request,
                                  file: UploadFile = File(...), db: Session = Depends(get_db)):
    """댓글 증빙 첨부(무인증). 조치상태 회신 댓글이면 해당 부서 발송이력 ack 증빙으로 동기화."""
    c = db.get(AdvisoryComment, comment_id)
    if not c:
        raise HTTPException(404, "댓글 없음")
    content = await file.read()
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(413, f"파일 크기 초과(최대 {settings.MAX_UPLOAD_MB}MB)")
    path = EVIDENCE_DIR / f"comment{comment_id}_{safe_filename(file.filename)}"
    path.write_bytes(content)
    c.evidence_path = str(path)
    c.evidence_name = file.filename

    # 조치상태 회신 + 부서 식별 가능 → (이 권고문, 부서) 최신 발송이력 증빙으로 동기화.
    synced = None
    if c.ack_status is not None and c.author_department_id is not None:
        n = db.scalar(
            select(Notification)
            .where(Notification.advisory_id == c.advisory_id,
                   Notification.department_id == c.author_department_id)
            .order_by(Notification.id.desc())
        )
        if n is not None:
            n.ack_evidence_path = str(path)
            n.ack_evidence_name = file.filename
            synced = n.id

    record(db, action="BOARD_COMMENT_EVIDENCE", actor_id=None, entity_type="advisory",
           entity_id=c.advisory_id, detail={"comment_id": comment_id, "file": file.filename,
                                            "ack_synced_notification": synced}, request=request)
    db.commit()
    db.refresh(c)
    return {"comment": serializers.comment_item(c), "ack_synced_notification": synced}


@router.get("/comments/{comment_id}/evidence")
def get_comment_evidence(comment_id: int, db: Session = Depends(get_db)):
    """댓글 증빙 파일 열람(inline). 첨부 없으면 404."""
    import os

    c = db.get(AdvisoryComment, comment_id)
    if not c or not c.evidence_path or not os.path.exists(c.evidence_path):
        raise HTTPException(404, "증빙 파일이 없습니다")
    return FileResponse(c.evidence_path, filename=c.evidence_name or "evidence",
                        headers={"Content-Disposition": f"inline; filename=\"{c.evidence_name or 'evidence'}\""})


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
