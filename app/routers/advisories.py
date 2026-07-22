"""보안권고문 — 업로드/추출/조회/PDF (명세서 §5.1, §4.1–4.3)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..config import UPLOAD_DIR, settings
from ..core import extract, product_extract
from ..core.matching import active_cves, all_cves_found
from ..db import SessionLocal, get_db
from ..deps import get_actor_id
from ..models import Advisory, AdvisoryCve, AdvisoryProduct, Cve, Match, Notification
from ..schemas import (
    AdvisoryMetaPatch,
    AdvisoryProductIn,
    AdvisoryProductPatch,
    BulkSourceRequest,
    CveAddRequest,
    CvePatchRequest,
    ProductApplyRequest,
)
from ..serializers import (
    _max_severity as serializers_max_severity,
    advisory_brief,
    advisory_cve_item,
    advisory_product_item,
)

router = APIRouter(prefix="/api/v1", tags=["advisories"])

# 비동기 추출용 작업 풀 — 업로드/추출 응답을 막지 않고 백그라운드에서 진행(보드가 상태 폴링).
_EXTRACT_POOL = ThreadPoolExecutor(max_workers=3, thread_name_prefix="extract")


@router.post("/advisories", status_code=201)
async def upload_advisory(
    request: Request,
    file: UploadFile = File(...),
    source_org: str = Form(""),
    receive_channel: str | None = Form(None),
    doc_no: str | None = Form(None),
    title: str | None = Form(None),
    due_at: str | None = Form(None),
    force: bool = Query(False),
    db: Session = Depends(get_db),
):
    content = await file.read()
    if len(content) > settings.max_upload_bytes:
        raise HTTPException(413, f"파일 크기 초과(최대 {settings.MAX_UPLOAD_MB}MB)")
    if not content[:5].startswith(b"%PDF"):
        raise HTTPException(400, "PDF 파일이 아닙니다(매직바이트 불일치).")
    # 출처기관은 선택(§개편) — 비워두면 '출처 미지정'으로 접수되고, 목록의
    # "빈 출처만 선택 → 일괄 지정" 흐름으로 나중에 채울 수 있다.
    source_org = (source_org or "").strip() or None
    # 접수경로(§9)는 본문 추출 우선이라 업로드 시 필수는 아니다. 단, 폼으로 값을 주면 유효해야 한다.
    form_channel = None
    rc = (receive_channel or "").strip()
    if rc:
        try:
            form_channel = enums.ReceiveChannel(rc)
        except ValueError as e:
            allowed = ", ".join(c.value for c in enums.ReceiveChannel)
            raise HTTPException(400, f"접수채널은 {allowed} 중 하나여야 합니다.") from e

    sha = extract.sha256_bytes(content)
    dup = db.scalar(select(Advisory).where(Advisory.file_sha256 == sha))
    if dup and not force:
        raise HTTPException(
            409,
            detail={
                "code": "DUPLICATE_PDF",
                "existing": {"id": dup.id, "doc_no": dup.doc_no, "title": dup.title},
            },
        )

    path = UPLOAD_DIR / f"{sha}.pdf"
    if not path.exists():
        path.write_bytes(content)
    text, pages = extract.extract_text_from_pdf(str(path))

    # 조치기한(§8): 본문 추출 우선 → 폼 수동입력 → 미지정(관리자 입력 대기).
    ext_due, _ = extract.extract_due_date(text)
    form_due = _parse_date(due_at)
    if ext_due is not None:
        final_due, due_source = ext_due, "PDF"
    elif form_due is not None:
        final_due, due_source = form_due, "MANUAL"
    else:
        final_due, due_source = None, None

    # 접수경로(§9): 본문 추출 우선 → 폼 수동선택(검증 완료) → 미지정. 기한과 동일 정책.
    ext_ch, _ = extract.extract_receive_channel(text)
    if ext_ch is not None:
        final_ch, ch_source = enums.ReceiveChannel(ext_ch), "PDF"
    elif form_channel is not None:
        final_ch, ch_source = form_channel, "MANUAL"
    else:
        final_ch, ch_source = None, None

    adv = Advisory(
        doc_no=(doc_no or "").strip() or None,
        title=(title or "").strip() or (file.filename or "보안권고문").rsplit(".", 1)[0],
        source_org=source_org,
        receive_channel=final_ch,
        channel_source=ch_source,
        received_at=date.today(),
        due_at=final_due,
        due_source=due_source,
        file_path=str(path),
        file_sha256=sha,
        page_count=pages,
        extracted_text=text,
        status=enums.AdvisoryStatus.UPLOADED,
        uploaded_by=get_actor_id(db),
    )
    db.add(adv)
    db.flush()
    record(db, action="ADVISORY_UPLOAD", actor_id=adv.uploaded_by,
           entity_type="advisory", entity_id=adv.id, detail={"sha256": sha, "force": force}, request=request)
    db.commit()
    return advisory_brief(adv)


@router.patch("/advisories/{advisory_id}/meta")
def update_meta(advisory_id: int, body: AdvisoryMetaPatch, request: Request,
                db: Session = Depends(get_db)):
    """조치기한·접수경로 관리자 수동 지정(§8·9) — 본문 미추출 시 직접 입력/수정.

    전달한 필드만 갱신하며, 설정 시 출처를 'MANUAL' 로 표기한다(빈 값이면 미지정으로 비움).
    """
    adv = _get(db, advisory_id)
    sent = body.model_fields_set
    if "source_org" in sent:
        adv.source_org = (body.source_org or "").strip() or None
    if "due_at" in sent:
        d = _parse_date(body.due_at)
        adv.due_at = d
        adv.due_source = "MANUAL" if d else None
    if "receive_channel" in sent:
        ch = (body.receive_channel or "").strip()
        if ch:
            try:
                adv.receive_channel = enums.ReceiveChannel(ch)
            except ValueError:
                raise HTTPException(400, "올바른 접수경로 값이 아닙니다(NCST·WEBMAIL·OFFICIAL_DOC).")
            adv.channel_source = "MANUAL"
        else:
            adv.receive_channel = None
            adv.channel_source = None
    record(db, action="ADVISORY_META_EDIT", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"due_at": str(adv.due_at) if adv.due_at else None,
                                     "channel": adv.receive_channel.value if adv.receive_channel else None},
           request=request)
    db.commit()
    return advisory_brief(adv)


@router.post("/advisories/{advisory_id}/extract")
def extract_cves(advisory_id: int, request: Request, db: Session = Depends(get_db)):
    """CVE 추출을 비동기로 시작(즉시 반환). 진행상태는 보드가 GET /advisories 로 폴링.

    extract_phase: queued → regex → done | failed. 실패/경고는 error_message.
    """
    adv = _get(db, advisory_id)
    # 중복 디스패치 방지: 이미 진행 중이면 재제출하지 않음(동시 추출 → uq_advisory_cve 충돌·오실패 방지).
    if adv.extract_phase in ("queued", "regex"):
        return {"advisory_id": advisory_id, "status": adv.status.value,
                "extract_phase": adv.extract_phase, "already_running": True}
    adv.status = enums.AdvisoryStatus.EXTRACTING
    adv.extract_phase = "queued"
    adv.error_message = None
    db.flush()
    record(db, action="ADVISORY_EXTRACT", actor_id=get_actor_id(db),
           entity_type="advisory", entity_id=adv.id, detail={"async": True}, request=request)
    db.commit()
    _EXTRACT_POOL.submit(_run_extract, advisory_id)
    return {"advisory_id": advisory_id, "status": adv.status.value, "extract_phase": "queued"}


def _run_extract(advisory_id: int) -> None:
    """백그라운드 추출 워커 — 자체 DB 세션. 단계별로 extract_phase 를 갱신·커밋해 보드가 본다."""
    db = None
    try:
        db = SessionLocal()  # try 내부에서 생성 → 세션 생성 실패도 failed 로 기록
        adv = db.get(Advisory, advisory_id)
        if not adv:
            return
        text = adv.extracted_text or ""
        adv.extract_phase = "regex"
        db.commit()

        # 재시도 대비: 저장 텍스트가 비어 있으면 원본 PDF 에서 다시 추출을 시도한다.
        if not text.strip() and adv.file_path:
            text, _pages = extract.extract_text_from_pdf(adv.file_path)
            if text.strip():
                adv.extracted_text = text

        # 스캔본(이미지) PDF: 텍스트가 없으면 '조용한 완료(CVE 0건)' 대신 실패로 안내하고
        # 기존(수동 추가 포함) CVE 를 보존한다 — 재시도 버튼 노출 + OCR/수동 입력 유도.
        if not text.strip():
            adv.extract_phase = "failed"
            adv.error_message = ("PDF에서 텍스트를 추출하지 못했습니다(스캔본·이미지 PDF 가능성). "
                                 "OCR 결과를 확인해 CVE를 수동 추가하세요.")
            if adv.status == enums.AdvisoryStatus.EXTRACTING:
                adv.status = enums.AdvisoryStatus.UPLOADED
            db.commit()
            return

        results = extract._regex_candidates(text)
        warning = None

        # 재처리 대비: 기존 추출 CVE 와 연결된 매칭을 함께 정리(FK 고립 방지) 후 재적재.
        # 수동 추가분(source_snippet='(수동 추가)')과 소프트 삭제분(관리자가 오추출로
        # 제거한 코드 — 재추출로 되살아나면 안 됨)은 보존한다(§개편).
        keep_codes = set()
        for ac in list(adv.cves):
            if (ac.source_snippet or "") == "(수동 추가)" or ac.is_deleted:
                keep_codes.add(ac.cve_id_text)
                continue
            for mt in db.scalars(select(Match).where(Match.advisory_cve_id == ac.id)):
                db.delete(mt)
            db.delete(ac)
        results = [c for c in results if c["cve_id_text"] not in keep_codes]
        db.flush()
        for c in results:
            cve = db.scalar(select(Cve).where(Cve.cve_id == c["cve_id_text"]))
            db.add(AdvisoryCve(
                advisory_id=adv.id, cve_id_text=c["cve_id_text"],
                cve_ref_id=cve.id if cve else None,
                lookup_status=enums.LookupStatus.FOUND if cve else enums.LookupStatus.NOT_FOUND,
                extraction_confidence=c.get("confidence"), source_snippet=c.get("source_snippet"),
            ))
        db.flush()

        # ── 영향 제품·버전 추출(§개편) — 관리자 확인/수동/삭제 이력은 보존하고
        #    이전 '추출 제안(SUGGESTED·EXTRACTED)'만 새 결과로 교체한다.
        _refresh_extracted_products(db, adv, text, revive_deleted=False)
        db.flush()
        db.refresh(adv)
        # 상태 판정은 보존된 수동 CVE 를 포함한 전체(삭제 제외) 기준.
        not_found = sum(1 for ac in adv.cves
                        if not ac.is_deleted and ac.lookup_status == enums.LookupStatus.NOT_FOUND)
        adv.status = (enums.AdvisoryStatus.NEEDS_CVE_UPDATE if not_found
                      else enums.AdvisoryStatus.EXTRACTED)
        adv.extract_phase = "done"
        adv.error_message = warning   # 경고는 표시하되 추출 자체는 완료
        db.commit()
    except Exception as e:  # noqa: BLE001 — 어떤 실패든 보드에서 보이게 기록
        try:
            if db is None:
                db = SessionLocal()
            else:
                db.rollback()
            adv = db.get(Advisory, advisory_id)
            if adv:
                adv.extract_phase = "failed"
                adv.error_message = f"추출 실패: {e}"[:500]
                db.commit()
        except Exception:
            pass
    finally:
        if db is not None:
            db.close()


def _refresh_extracted_products(db: Session, adv: Advisory, text: str,
                                *, revive_deleted: bool) -> int:
    """본문에서 제품·버전 추출 → advisory_product 갱신(§개편).

    · 이전 '추출 제안'(origin=EXTRACTED, status=SUGGESTED)은 새 결과로 교체.
    · CONFIRMED(관리자 확인)·MANUAL(수동 추가)은 유지.
    · DELETED 는 revive_deleted=False 면 유지(재추출로 되살아나지 않음 — 자동 재추출),
      True 면 다시 SUGGESTED 로 복원(관리자가 '수동 재추출'로 명시 요청한 경우).
    반환: 제안 건수.
    """
    extracted = product_extract.extract_products(text)
    keep_keys: set[str] = set()
    for p in list(adv.products):
        if p.status == "DELETED" and revive_deleted and p.origin == "EXTRACTED":
            db.delete(p)          # 곧바로 새 제안으로 재생성
            continue
        if p.origin == "EXTRACTED" and p.status == "SUGGESTED":
            db.delete(p)          # 이전 제안 → 새 결과로 교체
            continue
        keep_keys.add(p.product_key)
    db.flush()
    n = 0
    for item in extracted:
        if item["product_key"] in keep_keys:
            continue              # 관리자 확인/수동/삭제 이력이 우선
        db.add(AdvisoryProduct(
            advisory_id=adv.id,
            product_name=item["product_name"],
            product_key=item["product_key"],
            affected_versions=item["affected_versions"],
            fixed_version=item.get("fixed_version"),
            source_snippet=item.get("source_snippet"),
            confidence=item.get("confidence"),
            status="SUGGESTED",
            origin="EXTRACTED",
        ))
        n += 1
    return n


# ── 영향 제품·버전(§개편 — 추출 제안·수동 보정·복원·CVE 적용) ─────────────────


@router.get("/advisories/{advisory_id}/products")
def list_products(advisory_id: int, db: Session = Depends(get_db)):
    adv = _get(db, advisory_id)
    items = [advisory_product_item(p) for p in adv.products if p.status != "DELETED"]
    deleted = [advisory_product_item(p) for p in adv.products if p.status == "DELETED"]
    return {"items": items, "deleted": deleted,
            "summary": {"suggested": sum(1 for i in items if i["status"] == "SUGGESTED"),
                        "confirmed": sum(1 for i in items if i["status"] == "CONFIRMED"),
                        "deleted": len(deleted)}}


@router.post("/advisories/{advisory_id}/products", status_code=201)
def add_product(advisory_id: int, body: AdvisoryProductIn, request: Request,
                db: Session = Depends(get_db)):
    """영향 제품 수동 추가 — 추출이 놓친 제품 보정."""
    from ..core.normalize import normalize_product

    adv = _get(db, advisory_id)
    name = body.product_name.strip()
    if not name:
        raise HTTPException(400, "제품명을 입력하세요.")
    key = normalize_product(name)
    if any(p.product_key == key and p.status != "DELETED" for p in adv.products):
        raise HTTPException(409, "이미 등록된 제품입니다.")
    revived = next((p for p in adv.products if p.product_key == key and p.status == "DELETED"), None)
    if revived is not None:
        revived.status = "CONFIRMED"
        revived.product_name = name
        if body.affected_versions is not None:
            revived.affected_versions = body.affected_versions
        p = revived
    else:
        p = AdvisoryProduct(
            advisory_id=adv.id, product_name=name, product_key=key,
            affected_versions=body.affected_versions if body.affected_versions is not None else "*",
            fixed_version=(body.fixed_version or "").strip() or None,
            source_snippet="(수동 추가)", status="CONFIRMED", origin="MANUAL",
        )
        db.add(p)
    db.flush()
    record(db, action="PRODUCT_ADD_MANUAL", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"product": name, "key": key}, request=request)
    db.commit()
    return advisory_product_item(p)


@router.patch("/advisory-products/{product_id}")
def patch_product(product_id: int, body: AdvisoryProductPatch, request: Request,
                  db: Session = Depends(get_db)):
    """추출/등록된 제품을 그 자리에서 수정(§개편) — 이름·버전 규칙·조치버전·확인 상태."""
    from ..core.normalize import normalize_product

    p = db.get(AdvisoryProduct, product_id)
    if not p:
        raise HTTPException(404, "영향 제품 없음")
    sent = body.model_fields_set
    if "product_name" in sent and (body.product_name or "").strip():
        p.product_name = body.product_name.strip()
        new_key = normalize_product(p.product_name)
        if new_key != p.product_key:
            if any(q.id != p.id and q.product_key == new_key and q.status != "DELETED"
                   for q in p.advisory.products):
                raise HTTPException(409, "동일 제품키가 이미 등록되어 있습니다.")
            p.product_key = new_key
    if "affected_versions" in sent:
        p.affected_versions = body.affected_versions if body.affected_versions is not None else "*"
    if "fixed_version" in sent:
        p.fixed_version = (body.fixed_version or "").strip() or None
    if "status" in sent and body.status in ("SUGGESTED", "CONFIRMED"):
        p.status = body.status
    db.flush()
    record(db, action="PRODUCT_EDIT", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=p.advisory_id, detail={"product_id": p.id, "key": p.product_key,
                                            "versions": p.affected_versions}, request=request)
    db.commit()
    return advisory_product_item(p)


@router.delete("/advisory-products/{product_id}")
def delete_product(product_id: int, request: Request, db: Session = Depends(get_db)):
    """영향 제품 소프트 삭제 — 복원·수동 재추출로 되살릴 수 있다."""
    p = db.get(AdvisoryProduct, product_id)
    if not p:
        raise HTTPException(404, "영향 제품 없음")
    p.status = "DELETED"
    record(db, action="PRODUCT_DELETE", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=p.advisory_id, detail={"product_id": p.id, "key": p.product_key}, request=request)
    db.commit()
    return {"deleted": p.product_key, "restorable": True}


@router.post("/advisory-products/{product_id}/restore")
def restore_product(product_id: int, request: Request, db: Session = Depends(get_db)):
    """삭제한 영향 제품 복원(§개편 — 실수 삭제 되돌리기)."""
    p = db.get(AdvisoryProduct, product_id)
    if not p:
        raise HTTPException(404, "영향 제품 없음")
    if p.status != "DELETED":
        raise HTTPException(409, "삭제 상태가 아닙니다.")
    p.status = "SUGGESTED" if p.origin == "EXTRACTED" else "CONFIRMED"
    record(db, action="PRODUCT_RESTORE", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=p.advisory_id, detail={"product_id": p.id, "key": p.product_key}, request=request)
    db.commit()
    return advisory_product_item(p)


@router.post("/advisories/{advisory_id}/products/reextract")
def reextract_products(advisory_id: int, request: Request, db: Session = Depends(get_db)):
    """영향 제품 수동 재추출(§개편) — 삭제했던 추출 제안도 다시 제안 목록으로 복귀.

    잘못 삭제한 뒤 되돌릴 방법이 필요하다는 운영 요구 대응. CONFIRMED·MANUAL 은 유지된다.
    """
    adv = _get(db, advisory_id)
    text = adv.extracted_text or ""
    if not text.strip():
        raise HTTPException(409, "추출할 본문 텍스트가 없습니다(스캔본 PDF 가능성).")
    n = _refresh_extracted_products(db, adv, text, revive_deleted=True)
    record(db, action="PRODUCT_REEXTRACT", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"suggested": n}, request=request)
    db.commit()
    db.refresh(adv)
    return list_products(adv.id, db)


@router.post("/advisory-products/{product_id}/apply-to-cve")
def apply_product_to_cve(product_id: int, body: ProductApplyRequest, request: Request,
                         db: Session = Depends(get_db)):
    """추출 제품을 CVE 레코드에 적용(§개편) — 폐쇄망에서 피드 없이도 DB 미등록 해소.

    같은 권고문의 추출 CVE 를 대상으로:
      · 로컬 CVE 레코드가 없으면 생성(제품·버전 규칙 반영, source='ADVISORY').
      · 이미 있고 제품이 비어 있으면 primary 로 채움.
      · 이미 다른 제품이 있으면 affected_products 에 추가(다중 제품).
    적용 후 해당 추출 CVE 는 FOUND 로 전환되고 게이트가 재평가된다.
    """
    p = db.get(AdvisoryProduct, product_id)
    if not p:
        raise HTTPException(404, "영향 제품 없음")
    if p.status == "DELETED":
        raise HTTPException(409, "삭제된 제품은 적용할 수 없습니다. 먼저 복원하세요.")
    adv = p.advisory
    code = (body.cve_id or "").strip().upper().replace(" ", "-").replace("_", "-")
    ac = next((x for x in active_cves(adv) if x.cve_id_text == code), None)
    if ac is None:
        raise HTTPException(404, f"이 권고문의 추출 CVE 가 아닙니다: {code}")

    cve = db.scalar(select(Cve).where(Cve.cve_id == code))
    if cve is None:
        cve = Cve(cve_id=code, product_name=p.product_name, product_key=p.product_key,
                  affected_versions=p.affected_versions,
                  severity=enums.Severity.MEDIUM, source="ADVISORY",
                  description=f"권고문 추출 제품 적용: {adv.doc_no or adv.title or adv.id}")
        db.add(cve)
        db.flush()
    elif not cve.product_key:
        cve.product_name = p.product_name
        cve.product_key = p.product_key
        cve.affected_versions = p.affected_versions
    elif cve.product_key != p.product_key:
        extras = list(cve.affected_products or [])
        if all(e.get("product_key") != p.product_key for e in extras):
            extras.append({"product_name": p.product_name, "product_key": p.product_key,
                           "affected_versions": p.affected_versions})
            cve.affected_products = extras
    else:
        cve.affected_versions = p.affected_versions

    ac.cve_ref_id = cve.id
    ac.lookup_status = enums.LookupStatus.FOUND
    if p.status == "SUGGESTED":
        p.status = "CONFIRMED"
    db.flush()
    _reeval_status(adv)
    record(db, action="PRODUCT_APPLY_CVE", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"product_id": p.id, "key": p.product_key, "cve": code},
           request=request)
    db.commit()
    return {"applied": True, "cve": code, "product_key": p.product_key,
            "advisory_status": adv.status.value}


@router.post("/advisories/source-org")
def bulk_source_org(body: BulkSourceRequest, request: Request, db: Session = Depends(get_db)):
    """출처기관 일괄 지정(§개편). only_empty=True 면 출처가 빈 권고문만 갱신 —
    이미 지정된 출처를 실수로 덮어쓰지 않는다."""
    source = (body.source_org or "").strip()
    if not source:
        raise HTTPException(400, "출처기관을 입력하세요.")
    if not body.ids:
        raise HTTPException(400, "대상 권고문이 없습니다.")
    rows = db.scalars(select(Advisory).where(Advisory.id.in_(body.ids))).all()
    updated, skipped = [], []
    for adv in rows:
        if body.only_empty and (adv.source_org or "").strip():
            skipped.append(adv.id)
            continue
        adv.source_org = source
        updated.append(adv.id)
    record(db, action="ADVISORY_SOURCE_BULK", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=None, detail={"source": source, "updated": updated,
                                   "skipped": skipped, "only_empty": body.only_empty},
           request=request)
    db.commit()
    return {"updated": len(updated), "skipped": len(skipped), "source_org": source}


@router.get("/advisories/{advisory_id}/cves")
def list_cves(advisory_id: int, db: Session = Depends(get_db)):
    adv = _get(db, advisory_id)
    # CVE별 매칭 수(활성) 집계.
    counts = dict(
        db.execute(
            select(Match.advisory_cve_id, func.count(Match.id))
            .where(Match.advisory_id == adv.id, Match.status == enums.MatchStatus.MATCHED)
            .group_by(Match.advisory_cve_id)
        ).all()
    )
    live = [ac for ac in adv.cves if not ac.is_deleted]
    items = [advisory_cve_item(ac, match_count=counts.get(ac.id, 0)) for ac in live]
    deleted = [advisory_cve_item(ac) for ac in adv.cves if ac.is_deleted]
    return {
        "items": items,
        "deleted": deleted,   # 소프트 삭제분(§개편) — 화면에서 복원 가능
        "summary": {
            "extracted": len(items),
            "found": sum(1 for i in items if i["lookup_status"] == "FOUND"),
            "not_found": sum(1 for i in items if i["lookup_status"] == "NOT_FOUND"),
            "deleted": len(deleted),
        },
        "can_proceed": all_cves_found(adv),
    }


@router.post("/advisories/{advisory_id}/cves", status_code=201)
def add_cve(advisory_id: int, body: CveAddRequest, request: Request, db: Session = Depends(get_db)):
    """추출 CVE 수동 추가(§★★★) — 정규식이 놓친 코드 보정. 게이트 재평가."""
    adv = _get(db, advisory_id)
    m = extract.CVE_RE.search(body.cve_id.replace(" ", "-"))
    if not m:
        raise HTTPException(400, "올바른 CVE 코드 형식이 아닙니다.")
    # 표준형으로 정규화 — 'CVE_2026_1234' 같은 변형이 그대로 저장되면 CVE DB(cve_id 표준형)와
    # 영원히 불일치해 피드를 적용해도 게이트가 풀리지 않는다(백그라운드 추출과 동일 규칙).
    code = f"CVE-{m.group(1)}-{m.group(2)}"
    existing = next((ac for ac in adv.cves if ac.cve_id_text == code), None)
    if existing is not None and not existing.is_deleted:
        raise HTTPException(409, "이미 추출된 CVE입니다.")
    cve = db.scalar(select(Cve).where(Cve.cve_id == code))
    if existing is not None:
        # 소프트 삭제된 동일 코드 → 복원(§개편).
        existing.is_deleted = False
        existing.cve_ref_id = cve.id if cve else None
        existing.lookup_status = enums.LookupStatus.FOUND if cve else enums.LookupStatus.NOT_FOUND
        ac = existing
    else:
        ac = AdvisoryCve(
            advisory_id=adv.id, cve_id_text=code, cve_ref_id=cve.id if cve else None,
            lookup_status=enums.LookupStatus.FOUND if cve else enums.LookupStatus.NOT_FOUND,
            source_snippet="(수동 추가)",
        )
        db.add(ac)
    db.flush()
    _reeval_status(adv)
    record(db, action="CVE_ADD_MANUAL", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"cve": code}, request=request)
    db.commit()
    return advisory_cve_item(ac)


@router.patch("/advisory-cves/{ac_id}")
def patch_cve(ac_id: int, body: CvePatchRequest, request: Request, db: Session = Depends(get_db)):
    """추출 CVE 를 등록한 그 자리에서 수정(§개편) — 오추출 코드를 삭제/재등록 없이 교정.

    코드 변경 시 기존 매칭은 무효가 되므로 정리하고 DB 재조회·게이트 재평가한다.
    """
    ac = db.get(AdvisoryCve, ac_id)
    if not ac:
        raise HTTPException(404, "추출 CVE 없음")
    adv = ac.advisory
    m = extract.CVE_RE.search(body.cve_id.replace(" ", "-"))
    if not m:
        raise HTTPException(400, "올바른 CVE 코드 형식이 아닙니다.")
    new_code = f"CVE-{m.group(1)}-{m.group(2)}"
    old_code = ac.cve_id_text
    if new_code != old_code:
        if any(x.id != ac.id and x.cve_id_text == new_code and not x.is_deleted for x in adv.cves):
            raise HTTPException(409, "이미 추출된 CVE입니다.")
        for mt in db.scalars(select(Match).where(Match.advisory_cve_id == ac.id)):
            db.delete(mt)
        stale = next((x for x in adv.cves if x.id != ac.id and x.cve_id_text == new_code), None)
        if stale is not None:
            db.delete(stale)   # 같은 코드의 소프트 삭제 잔재는 흡수(UNIQUE 충돌 방지)
            db.flush()
        ac.cve_id_text = new_code
    cve = db.scalar(select(Cve).where(Cve.cve_id == ac.cve_id_text))
    ac.cve_ref_id = cve.id if cve else None
    ac.lookup_status = enums.LookupStatus.FOUND if cve else enums.LookupStatus.NOT_FOUND
    if (ac.source_snippet or "") != "(수동 추가)":
        ac.source_snippet = f"(관리자 수정: {old_code} → {new_code})"
    db.flush()
    _reeval_status(adv)
    record(db, action="CVE_EDIT_MANUAL", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"from": old_code, "to": new_code}, request=request)
    db.commit()
    return advisory_cve_item(ac)


@router.delete("/advisory-cves/{ac_id}")
def delete_cve(ac_id: int, request: Request, db: Session = Depends(get_db)):
    """추출 CVE 삭제(§★★★) — 소프트 삭제(§개편). 연결 매칭 정리, 게이트 재평가.

    행은 is_deleted=True 로 남아 '복원'이 가능하고, 재추출해도 되살아나지 않는다.
    """
    ac = db.get(AdvisoryCve, ac_id)
    if not ac:
        raise HTTPException(404, "추출 CVE 없음")
    adv = ac.advisory
    code = ac.cve_id_text
    for mt in db.scalars(select(Match).where(Match.advisory_cve_id == ac.id)):
        db.delete(mt)
    ac.is_deleted = True
    db.flush()
    _reeval_status(adv)
    record(db, action="CVE_DELETE_MANUAL", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"cve": code}, request=request)
    db.commit()
    return {"deleted": code, "restorable": True}


@router.post("/advisory-cves/{ac_id}/restore")
def restore_cve(ac_id: int, request: Request, db: Session = Depends(get_db)):
    """소프트 삭제한 추출 CVE 복원(§개편) — 실수 삭제 즉시 되돌리기."""
    ac = db.get(AdvisoryCve, ac_id)
    if not ac:
        raise HTTPException(404, "추출 CVE 없음")
    if not ac.is_deleted:
        raise HTTPException(409, "삭제 상태가 아닙니다.")
    ac.is_deleted = False
    cve = db.scalar(select(Cve).where(Cve.cve_id == ac.cve_id_text))
    ac.cve_ref_id = cve.id if cve else None
    ac.lookup_status = enums.LookupStatus.FOUND if cve else enums.LookupStatus.NOT_FOUND
    db.flush()
    _reeval_status(ac.advisory)
    record(db, action="CVE_RESTORE", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=ac.advisory_id, detail={"cve": ac.cve_id_text}, request=request)
    db.commit()
    return advisory_cve_item(ac)


def _reeval_status(adv: Advisory) -> None:
    """추출 CVE 변경 후 advisory 상태 재평가(게이트). 소프트 삭제분은 제외."""
    if not active_cves(adv):
        # 발송 이후 단계(NOTIFYING/COMPLETED/ARCHIVED)는 강등하지 않는다 —
        # 마지막 CVE 삭제로 발송된 권고문이 SLA/리마인드 대상에서 이탈하는 것 방지.
        if adv.status not in (enums.AdvisoryStatus.NOTIFYING, enums.AdvisoryStatus.COMPLETED,
                              enums.AdvisoryStatus.ARCHIVED):
            adv.status = enums.AdvisoryStatus.UPLOADED
        return
    if any(ac.lookup_status == enums.LookupStatus.NOT_FOUND for ac in active_cves(adv)):
        adv.status = enums.AdvisoryStatus.NEEDS_CVE_UPDATE
    elif adv.status in (enums.AdvisoryStatus.NEEDS_CVE_UPDATE, enums.AdvisoryStatus.UPLOADED,
                        enums.AdvisoryStatus.EXTRACTING):
        adv.status = enums.AdvisoryStatus.EXTRACTED


@router.get("/advisories/{advisory_id}/file")
def get_file(advisory_id: int, download: bool = Query(False), db: Session = Depends(get_db)):
    """원본 PDF 서빙. download=1 이면 첨부(다운로드), 아니면 inline(브라우저 열람)."""
    adv = _get(db, advisory_id)
    if not adv.file_path:
        raise HTTPException(404, "원본 PDF 없음")
    import os

    if not os.path.exists(adv.file_path):
        raise HTTPException(404, "원본 PDF 파일이 저장소에 없음")
    if download:
        from urllib.parse import quote

        ascii_name = _download_name(adv)
        utf8_name = quote((adv.doc_no or adv.title or f"advisory-{adv.id}") + ".pdf")
        disp = f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{utf8_name}"
    else:
        disp = "inline"
    return FileResponse(adv.file_path, media_type="application/pdf",
                        headers={"Content-Disposition": disp})


@router.get("/advisories/{advisory_id}/pdf-view")
def pdf_view(advisory_id: int, scale: float = Query(2.0, ge=1.0, le=4.0),
             db: Session = Depends(get_db)):
    """STEP2 원문 뷰어용 — 페이지 크기(px)와 추출 CVE 의 강조 박스. 렌더 불가 시 available=false."""
    adv = _get(db, advisory_id)
    if not adv.file_path:
        raise HTTPException(404, "원본 PDF 없음")
    import os

    if not os.path.exists(adv.file_path):
        raise HTTPException(404, "원본 PDF 파일이 저장소에 없음")
    terms = [ac.cve_id_text for ac in adv.cves if not ac.is_deleted]
    try:
        from ..core import pdf_render

        view = pdf_render.pdf_view(adv.file_path, terms, scale=scale)
    except Exception:  # noqa: BLE001 — 렌더러 부재/손상 PDF 시 텍스트 폴백 유지
        return {"available": False, "scale": scale, "pages": [], "boxes": []}
    view["available"] = bool(view["pages"])
    return view


@router.get("/advisories/{advisory_id}/page/{page}.png")
def get_page_png(advisory_id: int, page: int, scale: float = Query(2.0, ge=1.0, le=4.0),
                 db: Session = Depends(get_db)):
    """권고문 PDF 페이지(0-기반)를 PNG 로 렌더(서버 캐시)."""
    adv = _get(db, advisory_id)
    if not adv.file_path:
        raise HTTPException(404, "원본 PDF 없음")
    import os

    if not os.path.exists(adv.file_path):
        raise HTTPException(404, "원본 PDF 파일이 저장소에 없음")
    try:
        from ..core import pdf_render

        png = pdf_render.render_page_png(adv.file_path, page, scale=scale)
    except IndexError:
        raise HTTPException(404, "해당 페이지 없음")
    except Exception as e:  # noqa: BLE001
        raise HTTPException(500, f"PDF 렌더 실패: {e}")
    return Response(content=png, media_type="image/png",
                    headers={"Cache-Control": "public, max-age=86400"})


def _download_name(adv: Advisory) -> str:
    """ASCII 안전 폴백 파일명(latin-1 헤더용). 한글 원본명은 filename* 로 별도 전달."""
    base = (adv.doc_no or adv.title or f"advisory-{adv.id}").strip()
    safe = "".join(ch if (ch.isascii() and (ch.isalnum() or ch in "-_.")) else "_" for ch in base)
    return (safe.strip("_") or f"advisory-{adv.id}") + ".pdf"


@router.get("/advisories/{advisory_id}")
def get_advisory(advisory_id: int, db: Session = Depends(get_db)):
    adv = _get(db, advisory_id)
    mc = db.scalar(select(func.count(Match.id)).where(
        Match.advisory_id == adv.id, Match.status == enums.MatchStatus.MATCHED))
    return advisory_brief(adv, match_count=mc or 0)


@router.get("/advisories")
def list_advisories(
    status: str | None = None,
    source_org: str | None = None,
    page: int = 1,
    size: int = 50,
    db: Session = Depends(get_db),
):
    q = select(Advisory).order_by(Advisory.created_at.desc())
    if status:
        q = q.where(Advisory.status == enums.AdvisoryStatus(status))
    if source_org:
        q = q.where(Advisory.source_org == source_org)
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.limit(size).offset((page - 1) * size)).all()
    ids = [a.id for a in rows]

    # 보드 카드 시각화(§개편)용 롤업 — 매칭 자산 수/조치 완료 수, 발송 부서 수/회신 완료 수.
    match_counts: dict[int, tuple[int, int]] = {}
    notif_counts: dict[int, tuple[int, int]] = {}
    if ids:
        for adv_id, cnt, done in db.execute(
            select(Match.advisory_id, func.count(Match.id),
                   func.sum(case((Match.ack_status == enums.AckStatus.DONE, 1), else_=0)))
            .where(Match.advisory_id.in_(ids), Match.status == enums.MatchStatus.MATCHED)
            .group_by(Match.advisory_id)
        ).all():
            match_counts[adv_id] = (cnt or 0, int(done or 0))
        for adv_id, cnt, done in db.execute(
            select(Notification.advisory_id, func.count(Notification.id),
                   func.sum(case((Notification.ack_status == enums.AckStatus.DONE, 1), else_=0)))
            .where(Notification.advisory_id.in_(ids))
            .group_by(Notification.advisory_id)
        ).all():
            notif_counts[adv_id] = (cnt or 0, int(done or 0))

    items = []
    for a in rows:
        item = advisory_brief(a)
        mc, md = match_counts.get(a.id, (0, 0))
        nc, nd = notif_counts.get(a.id, (0, 0))
        item["match_count"] = mc
        item["asset_done"] = md
        item["notified_depts"] = nc
        item["acked_depts"] = nd
        item["max_severity"] = serializers_max_severity(a)
        items.append(item)
    return {"total": total, "items": items}


def _get(db: Session, advisory_id: int) -> Advisory:
    adv = db.get(Advisory, advisory_id)
    if not adv:
        raise HTTPException(404, "권고문을 찾을 수 없음")
    return adv


def _parse_date(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return datetime.strptime(s[:10], "%Y-%m-%d").date()
    except ValueError:
        return None
