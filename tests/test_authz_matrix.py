"""인가 경계 회귀망 — 무엇이 공개이고 무엇이 관리자 전용인지 전수 고정.

핵심은 test_every_non_public_route_requires_auth 다. 하드코딩한 목록이 아니라 실제
app.routes 를 순회하므로, 앞으로 게이트를 빠뜨린 라우터가 추가되면 여기서 잡힌다
(목록 방식은 새 엔드포인트를 조용히 놓친다).
"""
from __future__ import annotations

import re

import pytest

from app.main import app

# 무인증으로 열려 있어야 하는 경로 — 이 목록에 없으면 전부 인증을 요구해야 한다.
# 게시판(/api/v1/board/*)은 사내 누구나 쓰는 공개 표면이라는 의도된 설계다.
# 주의: /admin·/admin/history 는 무인증 접근이 허용된다는 뜻이 아니라, 401 대신
# 로그인 화면으로 303 하기 때문에 401 전수 검사에서 빼는 것이다(사람이 보는 화면이므로
# JSON 401 보다 리다이렉트가 옳다). 실제 게이트는 아래 셸 테스트가 확인한다.
PUBLIC_EXACT = {
    "/", "/board", "/admin", "/admin/history", "/api/health", "/favicon.ico",
    "/api/v1/auth/login",
    "/api/v1/board/departments",
    "/api/v1/board/advisories",
    "/api/v1/board/advisories/{advisory_id}",
    "/api/v1/board/advisories/{advisory_id}/file",
    "/api/v1/board/advisories/{advisory_id}/comments",
    "/api/v1/board/advisories/{advisory_id}/asset-ack",
    "/api/v1/board/comments/{comment_id}/evidence",   # POST 만 공개(GET 은 아래에서 별도 확인)
    # 웹훅은 쿠키가 아니라 HMAC 서명으로 인증한다(test_webhook_hmac.py 가 담당).
    "/api/v1/webhooks/groupware/ack",
}
PUBLIC_PREFIXES = ("/ui", "/openapi.json", "/docs", "/redoc")

# 관리자 전용이어야 하는 board 엔드포인트 — 위 PUBLIC_EXACT 의 예외.
BOARD_ADMIN_ONLY = {("GET", "/api/v1/board/comments/{comment_id}/evidence"),
                    ("DELETE", "/api/v1/board/comments/{comment_id}")}


def _is_public(method: str, path: str) -> bool:
    if (method, path) in BOARD_ADMIN_ONLY:
        return False
    return path in PUBLIC_EXACT or path.startswith(PUBLIC_PREFIXES)


def _concrete(path: str) -> str:
    """경로 파라미터를 존재하지 않는 ID 로 치환.

    require_admin 은 핸들러보다 먼저 돌기 때문에 404 가 아니라 401 이 나와야 한다 —
    '없는 자원' 응답이 먼저 나오면 그 자체로 게이트가 없다는 뜻이다.
    """
    return re.sub(r"\{[^}]+\}", "999999", path).replace("999999.png", "1.png")


def _routes():
    """등록된 전 엔드포인트 순회 — OpenAPI 스키마를 출처로 삼는다.

    app.routes 를 직접 읽지 않는 이유: 이 FastAPI 버전은 include_router 로 붙인 라우터를
    평탄화하지 않고 _IncludedRouter 로 감싸며, 그 객체는 path/methods/routes 중 무엇도
    노출하지 않는다. 눈치채지 못하면 기본 경로 4개만 순회하고 전수 검사가 조용히 통과한다.
    """
    for path, ops in app.openapi()["paths"].items():
        for method in ops:
            if method.upper() not in {"HEAD", "OPTIONS"}:
                yield method.upper(), path


NON_PUBLIC = sorted({(m, p) for m, p in _routes() if not _is_public(m, p)})
PUBLIC_BOARD = sorted({(m, p) for m, p in _routes()
                       if p.startswith("/api/v1/board") and _is_public(m, p)})


def test_route_inventory_is_not_empty():
    """치환·필터 로직이 망가져 0건을 순회하면 아래 전수 검사가 조용히 통과한다."""
    assert len(NON_PUBLIC) >= 50, NON_PUBLIC
    assert len(PUBLIC_BOARD) >= 7, PUBLIC_BOARD


@pytest.mark.parametrize(("method", "path"), NON_PUBLIC, ids=lambda v: str(v))
def test_every_non_public_route_requires_auth(public_client, method, path):
    r = public_client.request(method, _concrete(path))
    assert r.status_code == 401, f"{method} {path} → {r.status_code} (게이트 누락 의심)"
    assert r.json()["detail"]["code"] == "AUTH_REQUIRED"


@pytest.mark.parametrize(("method", "path"), PUBLIC_BOARD, ids=lambda v: str(v))
def test_public_board_routes_stay_anonymous(public_client, method, path):
    """게시판은 무인증 공개 유지 — 401/403 이 나오면 사내 직원 동선이 끊긴 것이다."""
    r = public_client.request(method, _concrete(path))
    assert r.status_code not in (401, 403), f"{method} {path} → {r.status_code}"


def test_health_open_anonymously(public_client):
    assert public_client.get("/api/health").json()["status"] == "ok"


# ── 관리자 정적 셸 ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("path", ["/admin", "/admin/history"])
def test_admin_shell_redirects_anonymous_to_login(public_client, path):
    r = public_client.get(path, follow_redirects=False)
    assert r.status_code == 303, r.status_code
    assert r.headers["location"].startswith("/ui/login.html?next=")
    assert path in r.headers["location"]


@pytest.mark.parametrize("path", ["/admin", "/admin/history"])
def test_admin_shell_served_to_logged_in_admin(client, path):
    r = client.get(path)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/html")
    assert r.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("path", [
    "/ui/app.dc.html", "/ui/history.html",
    "/ui/APP.DC.HTML",            # Windows 는 파일시스템이 대소문자를 구분하지 않는다
    "/ui/./app.dc.html", "/ui//app.dc.html",
])
def test_admin_html_unreachable_through_static_mount(public_client, path):
    """정적 마운트에는 관리자 HTML 이 아예 없다 — 경로 매칭 우회 자체가 성립하지 않는다."""
    r = public_client.get(path, follow_redirects=False)
    assert r.status_code == 404, f"{path} → {r.status_code}"


@pytest.mark.parametrize("path", ["/ui/board.html", "/ui/login.html", "/ui/support.js"])
def test_public_assets_still_served(public_client, path):
    assert public_client.get(path).status_code == 200


def test_admin_shell_sends_forced_change_user_to_password_screen(client):
    """강제 변경 중인 관리자는 SPA 셸이 아니라 비밀번호 변경 화면으로 가야 한다."""
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import AppUser

    with SessionLocal() as db:
        user = db.scalar(select(AppUser).where(AppUser.username == "testadmin"))
        user.must_change_password = True
        db.commit()
    try:
        r = client.get("/admin", follow_redirects=False)
        assert r.status_code == 303
        assert r.headers["location"] == "/ui/login.html?change=1"
    finally:
        with SessionLocal() as db:
            db.scalar(select(AppUser).where(AppUser.username == "testadmin")
                      ).must_change_password = False
            db.commit()


# ── 게시판 공개/비공개 경계의 실제 동작 ─────────────────────────────────────────

@pytest.fixture()
def published_comment(client):
    """게시판에 공개된 권고문 + 댓글 1건(익명으로 작성)."""
    from app.db import SessionLocal
    from app.models import Advisory, AdvisoryComment
    from app.seed import _minimal_pdf

    r = client.post("/api/v1/advisories",
                    files={"file": ("authz.pdf", _minimal_pdf("인가 경계 검증"), "application/pdf")},
                    data={"source_org": "검증기관", "title": "인가 경계 검증"})
    aid = r.json()["id"]
    assert client.post(f"/api/v1/advisories/{aid}/board").status_code == 200
    cid = client.post(f"/api/v1/board/advisories/{aid}/comments",
                      json={"author_name": "직원", "body": "회신합니다"}).json()["comment"]["id"]
    yield aid, cid
    with SessionLocal() as db:
        db.query(AdvisoryComment).filter(AdvisoryComment.advisory_id == aid).delete()
        db.query(Advisory).filter(Advisory.id == aid).delete()
        db.commit()


def test_comment_post_stays_public(public_client, published_comment):
    """직원 회신은 로그인 없이, CSRF 헤더 없이도 가능해야 한다."""
    aid, _ = published_comment
    r = public_client.post(f"/api/v1/board/advisories/{aid}/comments",
                           json={"author_name": "타직원", "body": "저도 회신합니다"})
    assert r.status_code == 201, r.text


def test_evidence_upload_public_but_read_is_admin_only(public_client, client, published_comment):
    """H-1: 업로드는 공개, 열람은 관리자 — ID 열거로 전 부서 증빙이 새던 경로를 막는다."""
    _, cid = published_comment
    up = public_client.post(f"/api/v1/board/comments/{cid}/evidence",
                            files={"file": ("proof.txt", b"proof", "text/plain")})
    assert up.status_code == 201, up.text

    assert public_client.get(f"/api/v1/board/comments/{cid}/evidence").status_code == 401
    admin = client.get(f"/api/v1/board/comments/{cid}/evidence")
    assert admin.status_code == 200
    assert admin.content == b"proof"


def test_delete_comment_is_admin_only(public_client, client, published_comment):
    """H-2: 익명 삭제 거부 + 댓글이 실제로 살아 있어야 한다."""
    aid, cid = published_comment
    assert public_client.delete(f"/api/v1/board/comments/{cid}").status_code == 401
    listed = public_client.get(f"/api/v1/board/advisories/{aid}/comments").json()["items"]
    assert any(c["id"] == cid for c in listed), "익명 삭제가 실제로 먹혔다"
    assert client.delete(f"/api/v1/board/comments/{cid}").status_code == 204


def test_audit_records_real_logged_in_actor(client, published_comment):
    """감사 로그의 actor_id 가 ANALYST 폴백이 아니라 실제 로그인 계정이어야 한다.

    조치 전에는 get_actor_id 가 '활성 ANALYST 행 아무거나'를 주체로 기록해, 감사 로그가
    누가 했는지 말해 주지 못했다. 업로드(권고문)와 모더레이션(댓글 삭제) 양쪽을 확인한다.
    """
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import Advisory, AppUser, AuditLog

    aid, cid = published_comment
    with SessionLocal() as db:
        admin_id = db.scalar(select(AppUser.id).where(AppUser.username == "testadmin"))
        upload = db.scalar(select(AuditLog).where(AuditLog.action == "ADVISORY_UPLOAD",
                                                  AuditLog.entity_id == aid))
        assert upload is not None and upload.actor_id == admin_id
        # 업로더 컬럼도 실제 사용자여야 한다(감사 로그와 별개 경로).
        assert db.get(Advisory, aid).uploaded_by == admin_id

    assert client.delete(f"/api/v1/board/comments/{cid}").status_code == 204
    with SessionLocal() as db:
        deleted = db.scalar(select(AuditLog)
                            .where(AuditLog.action == "BOARD_COMMENT_DELETE",
                                   AuditLog.entity_id == aid)
                            .order_by(AuditLog.id.desc()))
        assert deleted is not None and deleted.actor_id == admin_id
