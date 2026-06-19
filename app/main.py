"""FastAPI 진입점 — 보안권고문 처리 시스템 백엔드."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from .config import WEB_DIR, settings
from .db import SessionLocal, init_db
from .routers import (
    advisories, assets, audit, board, cve_feeds, cves, dashboard, departments, history, matches,
    notifications, remediation,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if settings.SEED_ON_START:
        from .seed import seed

        with SessionLocal() as db:
            seed(db)
    if settings.LOAD_BUNDLED_FEEDS:
        _load_bundled_cve_feeds()
    _reconcile_stuck_extractions()
    yield


def _load_bundled_cve_feeds() -> None:
    """동봉된 CVE 피드(samples/cve_feeds/*)를 최초 1회 cve 테이블에 적재 — 폐쇄망 즉시 사용.

    소스: NVD(Public Domain) · CISA KEV(Public Domain) · KISA. 멱등(표식 파일로 1회만).
    대량 적재 시 SQLite 변수 한계(999) 회피를 위해 배치 단위로 upsert·커밋한다.
    """
    from .config import BASE_DIR, DATA_DIR
    from .core import feeds

    feed_dir = BASE_DIR / "samples" / "cve_feeds"
    sentinel = DATA_DIR / ".cve_feeds_loaded"
    if not feed_dir.exists() or sentinel.exists():
        return
    total_added = 0
    with SessionLocal() as db:
        for f in sorted(feed_dir.glob("*.json")):
            try:
                records = feeds.parse_feed(f.name, f.read_bytes())
            except Exception:  # noqa: BLE001 — 깨진 피드 한 건이 부팅을 막지 않게
                continue
            for i in range(0, len(records), 500):  # SQLite IN 한계(999) 회피
                added, _ = feeds.apply_records(db, records[i:i + 500], None)
                total_added += added
                db.commit()
    sentinel.write_text(str(total_added), encoding="utf-8")
    if total_added:
        print(f"[cve-feeds] 동봉 CVE 피드 적재 완료: {total_added}건", flush=True)


def _reconcile_stuck_extractions() -> None:
    """비정상 종료로 중단된 추출 작업 정리 — 재시작 시 stuck(queued/regex) 해제."""
    from sqlalchemy import select

    from . import enums
    from .models import Advisory

    with SessionLocal() as db:
        stuck = db.scalars(
            select(Advisory).where(Advisory.extract_phase.in_(["queued", "regex"]))
        ).all()
        for a in stuck:
            a.extract_phase = "failed"
            a.error_message = "추출 중단됨(서버 재시작) — 다시 시도하세요"
            if a.status == enums.AdvisoryStatus.EXTRACTING:
                a.status = enums.AdvisoryStatus.UPLOADED
        if stuck:
            db.commit()


app = FastAPI(title="보안권고문 처리 시스템 API", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS or ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

for r in (advisories, cve_feeds, cves, assets, matches, notifications, departments, dashboard,
          remediation, audit, board, history):
    app.include_router(r.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "1.0.0"}


# 프론트엔드(DC SPA) 정적 서빙. 동일 출처에서 /api/v1 호출.
if WEB_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(WEB_DIR), html=True), name="ui")


@app.get("/")
def root():
    # 일반 사용자 진입점 = 내부 게시판. 관리자는 /admin.
    return RedirectResponse(url="/board")


@app.get("/board")
def board_page():
    return RedirectResponse(url="/ui/board.html")


@app.get("/admin")
def admin_page():
    return RedirectResponse(url="/ui/app.dc.html")


@app.get("/admin/history")
def admin_history_page():
    # 발송이력·조치관리 콘솔(마스터-디테일). 기존 관리자 SPA 와 분리된 독립 페이지.
    return RedirectResponse(url="/ui/history.html")
