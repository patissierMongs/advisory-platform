"""보안권고문 — 업로드/추출/조회/PDF (명세서 §5.1, §4.1–4.3)."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import enums
from ..audit import record
from ..config import UPLOAD_DIR, settings
from ..core import appconfig, extract, gate_extract, source_detect
from ..core.matching import all_cves_found
from ..db import SessionLocal, get_db
from ..deps import get_actor_id
from ..models import Advisory, AdvisoryCve, Cve, Match
from ..schemas import AdvisoryMetaPatch, CveAddRequest, SourceBatchPatch
from ..serializers import advisory_brief, advisory_cve_item

router = APIRouter(prefix="/api/v1", tags=["advisories"])

# 비동기 추출용 작업 풀 — 업로드/추출 응답을 막지 않고 백그라운드에서 진행(보드가 상태 폴링).
_EXTRACT_POOL = ThreadPoolExecutor(max_workers=3, thread_name_prefix="extract")


@router.post("/advisories", status_code=201)
async def upload_advisory(
    request: Request,
    file: UploadFile = File(...),
    source_org: str = Form(""),
    rel_path: str | None = Form(None),
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
    # 출처(§출처): 직접 입력은 더 이상 필수가 아니다 — 업로드 후 자동 탐지가 기본.
    source_org = (source_org or "").strip()
    rel_path = (rel_path or "").strip() or None
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

    # 출처(§출처): 상위 폴더명 → 폴더명 → 파일명 → 본문 순으로 자동 탐지.
    # 후보 목록은 항상 저장(화면에서 나열·클릭 선택). 직접 입력이 있으면 MANUAL 우선,
    # 탐지 성공이면 최우선 후보로 자동 지정, 실패면 '-'(관리자가 이후 지정 가능).
    candidates = source_detect.detect_sources(rel_path, file.filename, text)
    if source_org:
        final_src, src_origin = source_org, "MANUAL"
    elif candidates:
        final_src, src_origin = candidates[0]["name"], candidates[0]["origin"]
    else:
        final_src, src_origin = "-", None

    adv = Advisory(
        doc_no=(doc_no or "").strip() or None,
        title=(title or "").strip() or (file.filename or "보안권고문").rsplit(".", 1)[0],
        source_org=final_src,
        source_origin=src_origin,
        source_candidates=candidates,
        rel_path=rel_path,
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


@router.patch("/advisories/source-batch")
def update_source_batch(body: SourceBatchPatch, request: Request, db: Session = Depends(get_db)):
    """출처 일괄 지정(§출처) — 업로드 배치 전체에 선택 후보/직접 입력을 한번에 적용.

    복수 출처 선택 시 ', ' 로 연결해 복수 출처로 기록한다. 빈 목록이면 '-' 로 지정.
    """
    sources = [s.strip() for s in body.sources if s and s.strip()]
    joined = ", ".join(dict.fromkeys(sources)) or "-"
    items = []
    for aid in body.ids:
        adv = db.get(Advisory, aid)
        if not adv:
            continue
        adv.source_org = joined
        adv.source_origin = "MANUAL" if joined != "-" else None
        items.append(adv)
    record(db, action="ADVISORY_SOURCE_BATCH", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=None, detail={"ids": body.ids, "source": joined}, request=request)
    db.commit()
    return {"applied": len(items), "source_org": joined,
            "items": [advisory_brief(a) for a in items]}


@router.patch("/advisories/{advisory_id}/meta")
def update_meta(advisory_id: int, body: AdvisoryMetaPatch, request: Request,
                db: Session = Depends(get_db)):
    """조치기한·접수경로·출처 관리자 수동 지정(§8·9·출처) — 본문 미추출 시 직접 입력/수정.

    전달한 필드만 갱신하며, 설정 시 출처를 'MANUAL' 로 표기한다(빈 값이면 미지정으로 비움).
    """
    adv = _get(db, advisory_id)
    sent = body.model_fields_set
    if "source_org" in sent:
        # 출처는 항상 값을 가진다 — 비우면 '-'(미탐지 표기)로 지정(§출처).
        src = ", ".join(dict.fromkeys(
            s.strip() for s in (body.source_org or "").split(",") if s.strip()))
        adv.source_org = src or "-"
        adv.source_origin = "MANUAL" if src else None
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
        # 수동 추가분(source_snippet='(수동 추가)')은 관리자 보정이므로 보존한다.
        manual_codes = set()
        for ac in list(adv.cves):
            if (ac.source_snippet or "") == "(수동 추가)":
                manual_codes.add(ac.cve_id_text)
                continue
            for mt in db.scalars(select(Match).where(Match.advisory_cve_id == ac.id)):
                db.delete(mt)
            db.delete(ac)
        results = [c for c in results if c["cve_id_text"] not in manual_codes]
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
        db.refresh(adv)
        # 상태 판정은 보존된 수동 CVE 를 포함한 전체 기준.
        not_found = sum(1 for ac in adv.cves if ac.lookup_status == enums.LookupStatus.NOT_FOUND)
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
    items = [advisory_cve_item(ac, match_count=counts.get(ac.id, 0)) for ac in adv.cves]
    return {
        "items": items,
        "summary": {
            "extracted": len(items),
            "found": sum(1 for i in items if i["lookup_status"] == "FOUND"),
            "not_found": sum(1 for i in items if i["lookup_status"] == "NOT_FOUND"),
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
    if any(ac.cve_id_text == code for ac in adv.cves):
        raise HTTPException(409, "이미 추출된 CVE입니다.")
    cve = db.scalar(select(Cve).where(Cve.cve_id == code))
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


@router.delete("/advisory-cves/{ac_id}")
def delete_cve(ac_id: int, request: Request, db: Session = Depends(get_db)):
    """추출 CVE 삭제(§★★★) — 오추출 제거. 연결 매칭도 정리, 게이트 재평가."""
    ac = db.get(AdvisoryCve, ac_id)
    if not ac:
        raise HTTPException(404, "추출 CVE 없음")
    adv = ac.advisory
    code = ac.cve_id_text
    for mt in db.scalars(select(Match).where(Match.advisory_cve_id == ac.id)):
        db.delete(mt)
    db.delete(ac)
    db.flush()
    _reeval_status(adv)
    record(db, action="CVE_DELETE_MANUAL", actor_id=get_actor_id(db), entity_type="advisory",
           entity_id=adv.id, detail={"cve": code}, request=request)
    db.commit()
    return {"deleted": code}


def _reeval_status(adv: Advisory) -> None:
    """추출 CVE 변경 후 advisory 상태 재평가(게이트)."""
    if not adv.cves:
        # 발송 이후 단계(NOTIFYING/COMPLETED/ARCHIVED)는 강등하지 않는다 —
        # 마지막 CVE 삭제로 발송된 권고문이 SLA/리마인드 대상에서 이탈하는 것 방지.
        if adv.status not in (enums.AdvisoryStatus.NOTIFYING, enums.AdvisoryStatus.COMPLETED,
                              enums.AdvisoryStatus.ARCHIVED):
            adv.status = enums.AdvisoryStatus.UPLOADED
        return
    if any(ac.lookup_status == enums.LookupStatus.NOT_FOUND for ac in adv.cves):
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


@router.get("/advisories/{advisory_id}/gate")
def gate_info(advisory_id: int, db: Session = Depends(get_db)):
    """CVE 게이트 보조(§게이트) — DB 미등록 CVE 별 수동 등록 폼 기본값(본문 자동 추출).

    제품·버전·날짜 제안과 매칭 근거(카테고리별 색)를 반환한다. 색은 product_catalog
    설정 파일의 값 그대로 — STEP2 PDF 하이라이트와 항상 동일하다.
    """
    adv = _get(db, advisory_id)
    catalog = appconfig.get_config("product_catalog")
    missing = [ac.cve_id_text for ac in adv.cves
               if ac.lookup_status == enums.LookupStatus.NOT_FOUND]
    ga = gate_extract.analyze(adv.extracted_text or "", missing, catalog)
    src = adv.source_org if (adv.source_org and adv.source_org != "-") else None
    items = [{"cve_id": code,
              "suggest": dict(ga["items"].get(code) or {}, source=src)} for code in missing]
    return {
        "items": items,
        "colors": ga["colors"],
        "products": ga["products"],       # 본문에서 매칭된 제품(근거 칩 — PDF 와 동일 색)
        "versions": ga["versions"],
        "dates": ga["dates"],
        # 카탈로그 전체(빠른 선택·인라인 편집용) — 파일: data/config/product_catalog.json
        "catalog": {
            "products": [{"key": p.get("key"), "label": p.get("label"),
                          "color": p.get("color"), "patterns": p.get("patterns", [])}
                         for p in catalog.get("products", [])],
            "version_patterns": catalog.get("version_patterns", []),
        },
    }


@router.get("/advisories/{advisory_id}/pdf-view")
def pdf_view(advisory_id: int, scale: float = Query(2.0, ge=1.0, le=4.0),
             db: Session = Depends(get_db)):
    """STEP2 원문 뷰어용 — 페이지 크기(px)와 강조 박스. 렌더 불가 시 available=false.

    강조 대상: 추출 CVE(항상) + 게이트 활성 시(미등록 CVE 존재) 제품·버전·날짜 자동
    매칭 문자열. 색은 product_catalog 설정과 동일 — 게이트 폼 근거 칩과 항상 같은 색.
    """
    adv = _get(db, advisory_id)
    if not adv.file_path:
        raise HTTPException(404, "원본 PDF 없음")
    import os

    if not os.path.exists(adv.file_path):
        raise HTTPException(404, "원본 PDF 파일이 저장소에 없음")
    try:
        catalog = appconfig.get_config("product_catalog")
    except ValueError:
        catalog = {}
    colors = (catalog.get("colors") or {}) if isinstance(catalog, dict) else {}
    cve_color = colors.get("cve", "#e8a33d")
    terms: list[dict] = [{"term": ac.cve_id_text, "category": "cve", "color": cve_color}
                         for ac in adv.cves]
    legend = [{"category": "cve", "label": "추출된 CVE", "color": cve_color}]
    missing = [ac.cve_id_text for ac in adv.cves
               if ac.lookup_status == enums.LookupStatus.NOT_FOUND]
    if missing and catalog:
        ga = gate_extract.analyze(adv.extracted_text or "", missing, catalog)
        terms += ga["highlight_terms"]
        for p in ga["products"]:
            legend.append({"category": "product", "label": p["label"], "color": p["color"]})
        if ga["versions"]:
            legend.append({"category": "version", "label": "버전 표기", "color": ga["colors"]["version"]})
        if ga["dates"]:
            legend.append({"category": "date", "label": "날짜 표기", "color": ga["colors"]["date"]})
    try:
        from ..core import pdf_render

        view = pdf_render.pdf_view(adv.file_path, terms, scale=scale)
    except Exception:  # noqa: BLE001 — 렌더러 부재/손상 PDF 시 텍스트 폴백 유지
        return {"available": False, "scale": scale, "pages": [], "boxes": [], "legend": legend}
    view["available"] = bool(view["pages"])
    view["legend"] = legend
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
        # 복수 출처(', ' 연결) 지원 — 부분 일치로 조회(§출처).
        q = q.where(Advisory.source_org.ilike(f"%{source_org}%"))
    total = db.scalar(select(func.count()).select_from(q.subquery()))
    rows = db.scalars(q.limit(size).offset((page - 1) * size)).all()
    return {"total": total, "items": [advisory_brief(a) for a in rows]}


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
