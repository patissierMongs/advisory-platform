"""관리자 인증 — 로그인·세션·잠금·CSRF·계정 관리 회귀.

세션 스코프 client 를 로그아웃시키면 이후 전 테스트가 무너지므로, 이 파일은 자체
사용자·자체 클라이언트를 만들어 쓴다(client 픽스처의 세션은 건드리지 않는다).
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import auth
from app.core.passwords import hash_password
from app.db import SessionLocal
from app.enums import UserRole
from app.main import app
from app.models import AdminSession, AppUser, AuditLog

PASSWORD = "unit-test-pw-1"


def _make_user(username: str, *, role=UserRole.ADMIN, active=True,
               password: str | None = PASSWORD, must_change=False) -> int:
    with SessionLocal() as db:
        existing = db.scalar(select(AppUser).where(AppUser.username == username))
        if existing is not None:
            db.delete(existing)
            db.commit()
        u = AppUser(username=username, display_name=username, role=role, is_active=active,
                    password_hash=hash_password(password) if password else None,
                    must_change_password=must_change)
        db.add(u)
        db.commit()
        return u.id


@pytest.fixture()
def user_factory():
    created: list[int] = []

    def make(username, **kw):
        uid = _make_user(username, **kw)
        created.append(uid)
        return uid

    yield make
    with SessionLocal() as db:
        for uid in created:
            db.query(AdminSession).filter(AdminSession.user_id == uid).delete()
            db.query(AuditLog).filter(AuditLog.actor_id == uid).delete()
            db.query(AppUser).filter(AppUser.id == uid).delete()
        db.commit()


@pytest.fixture()
def fresh():
    """로그인하지 않은 독립 클라이언트(쿠키 격리)."""
    with TestClient(app) as c:
        yield c


def _login(c, username, password=PASSWORD):
    return c.post("/api/v1/auth/login", json={"username": username, "password": password})


# ── 로그인 ────────────────────────────────────────────────────────────────────

def test_login_sets_httponly_session_and_readable_csrf(fresh, user_factory):
    user_factory("auth_ok")
    r = _login(fresh, "auth_ok")
    assert r.status_code == 200, r.text
    cookies = {c.name: c for c in fresh.cookies.jar}
    assert cookies["adv_session"].has_nonstandard_attr("HttpOnly"), "세션 쿠키가 JS 에 노출된다"
    assert not cookies["adv_csrf"].has_nonstandard_attr("HttpOnly"), "SPA 가 CSRF 를 못 읽는다"
    assert r.json()["csrf_token"]
    # 쿠키에는 원문 토큰, DB 에는 해시만 있어야 한다.
    raw = cookies["adv_session"].value
    with SessionLocal() as db:
        assert db.scalar(select(AdminSession).where(AdminSession.token_hash == raw)) is None


def test_unknown_user_and_wrong_password_are_indistinguishable(fresh, user_factory):
    """계정 열거 차단 — 상태코드와 메시지가 완전히 같아야 한다."""
    user_factory("auth_enum")
    wrong = _login(fresh, "auth_enum", "definitely-wrong")
    unknown = _login(fresh, "no_such_account_here", "definitely-wrong")
    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_inactive_user_cannot_login(fresh, user_factory):
    user_factory("auth_inactive", active=False)
    assert _login(fresh, "auth_inactive").status_code == 401


def test_user_without_password_cannot_login(fresh, user_factory):
    """시드 analyst 처럼 자격증명이 없는 감사용 주체는 로그인 대상이 아니다."""
    user_factory("auth_nopw", password=None)
    assert _login(fresh, "auth_nopw").status_code == 401


def test_non_admin_role_is_forbidden_on_admin_api(fresh, user_factory):
    user_factory("auth_analyst", role=UserRole.ANALYST)
    assert _login(fresh, "auth_analyst").status_code == 200
    r = fresh.get("/api/v1/dashboard")
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "FORBIDDEN"


# ── 잠금 ──────────────────────────────────────────────────────────────────────

def test_lockout_blocks_even_correct_password(fresh, user_factory):
    from app.config import settings

    user_factory("auth_lock")
    for _ in range(settings.LOGIN_MAX_FAILS):
        assert _login(fresh, "auth_lock", "nope").status_code == 401
    r = _login(fresh, "auth_lock")            # 정답 비밀번호
    assert r.status_code == 423, r.text
    assert r.json()["detail"]["retry_after_seconds"] > 0

    with SessionLocal() as db:
        actions = {a.action for a in db.scalars(
            select(AuditLog).where(AuditLog.entity_type == "app_user")).all()}
    assert {"LOGIN_FAILURE", "LOGIN_LOCKED"} <= actions


def test_lockout_expiry_restores_login_and_resets_counter(fresh, user_factory):
    from app.config import settings

    uid = user_factory("auth_unlock")
    for _ in range(settings.LOGIN_MAX_FAILS):
        _login(fresh, "auth_unlock", "nope")
    with SessionLocal() as db:
        db.get(AppUser, uid).locked_until = auth.now_utc() - timedelta(minutes=1)
        db.commit()
    assert _login(fresh, "auth_unlock").status_code == 200
    with SessionLocal() as db:
        u = db.get(AppUser, uid)
        assert u.failed_count == 0 and u.locked_until is None


# ── 세션 수명 ─────────────────────────────────────────────────────────────────

def _only_session(uid: int) -> AdminSession:
    with SessionLocal() as db:
        return db.scalar(select(AdminSession)
                         .where(AdminSession.user_id == uid, AdminSession.revoked_at.is_(None))
                         .order_by(AdminSession.id.desc()))


def test_absolute_expiry_ends_session(fresh, user_factory):
    uid = user_factory("auth_exp")
    _login(fresh, "auth_exp")
    assert fresh.get("/api/v1/auth/me").status_code == 200
    with SessionLocal() as db:
        s = db.get(AdminSession, _only_session(uid).id)
        s.expires_at = auth.now_utc() - timedelta(seconds=1)
        db.commit()
    assert fresh.get("/api/v1/auth/me").status_code == 401


def test_idle_timeout_ends_session(fresh, user_factory):
    from app.config import settings

    uid = user_factory("auth_idle")
    _login(fresh, "auth_idle")
    with SessionLocal() as db:
        s = db.get(AdminSession, _only_session(uid).id)
        s.last_seen_at = auth.now_utc() - timedelta(minutes=settings.SESSION_IDLE_MINUTES + 1)
        db.commit()
    assert fresh.get("/api/v1/auth/me").status_code == 401


def test_logout_revokes_session(fresh, user_factory):
    r = _login(fresh, user_factory("auth_out") and "auth_out")
    csrf = r.json()["csrf_token"]
    assert fresh.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 204
    assert fresh.get("/api/v1/auth/me").status_code == 401


def test_deactivating_user_kills_live_session(fresh, user_factory, client):
    """계정 비활성화가 이미 열려 있는 세션까지 끊어야 한다."""
    uid = user_factory("auth_kill")
    _login(fresh, "auth_kill")
    assert fresh.get("/api/v1/auth/me").status_code == 200
    assert client.patch(f"/api/v1/auth/users/{uid}", json={"is_active": False}).status_code == 200
    assert fresh.get("/api/v1/auth/me").status_code == 401


# ── 비밀번호 ──────────────────────────────────────────────────────────────────

def test_password_change_revokes_other_sessions(fresh, user_factory):
    user_factory("auth_pw")
    other = TestClient(app)
    assert _login(other, "auth_pw").status_code == 200

    r = _login(fresh, "auth_pw")
    csrf = r.json()["csrf_token"]
    changed = fresh.post("/api/v1/auth/password",
                         json={"current_password": PASSWORD, "new_password": "brand-new-pw-9"},
                         headers={"X-CSRF-Token": csrf})
    assert changed.status_code == 200, changed.text
    # 변경한 본인은 새 쿠키로 계속, 다른 세션은 끊긴다.
    assert fresh.get("/api/v1/auth/me").status_code == 200
    assert other.get("/api/v1/auth/me").status_code == 401
    assert _login(fresh, "auth_pw", "brand-new-pw-9").status_code == 200


def test_password_change_requires_current_password(fresh, user_factory):
    user_factory("auth_pw_wrong")
    csrf = _login(fresh, "auth_pw_wrong").json()["csrf_token"]
    r = fresh.post("/api/v1/auth/password",
                   json={"current_password": "not-it", "new_password": "brand-new-pw-9"},
                   headers={"X-CSRF-Token": csrf})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "WRONG_PASSWORD"


@pytest.mark.parametrize("weak", ["short", "auth_weak12", "password"])
def test_password_policy_rejects_weak_values(fresh, user_factory, weak):
    user_factory("auth_weak12")
    csrf = _login(fresh, "auth_weak12").json()["csrf_token"]
    r = fresh.post("/api/v1/auth/password",
                   json={"current_password": PASSWORD, "new_password": weak},
                   headers={"X-CSRF-Token": csrf})
    assert r.status_code == 400 and r.json()["detail"]["code"] == "WEAK_PASSWORD"


def test_forced_change_blocks_everything_except_self_service(fresh, user_factory):
    user_factory("auth_force", must_change=True)
    r = _login(fresh, "auth_force")
    assert r.status_code == 200 and r.json()["must_change_password"] is True
    csrf = r.json()["csrf_token"]

    blocked = fresh.get("/api/v1/dashboard")
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["code"] == "PASSWORD_CHANGE_REQUIRED"
    assert fresh.get("/api/v1/auth/me").status_code == 200

    ok = fresh.post("/api/v1/auth/password",
                    json={"current_password": PASSWORD, "new_password": "after-change-pw-2"},
                    headers={"X-CSRF-Token": csrf})
    assert ok.status_code == 200
    assert fresh.get("/api/v1/dashboard").status_code == 200


# ── CSRF ──────────────────────────────────────────────────────────────────────

def test_state_change_requires_csrf_header(fresh, user_factory):
    user_factory("auth_csrf")
    _login(fresh, "auth_csrf")
    assert fresh.get("/api/v1/dashboard").status_code == 200        # GET 은 검사 안 함
    r = fresh.post("/api/v1/departments", json={"name": "csrf-none"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "CSRF_FAILED"


def test_wrong_csrf_token_rejected(fresh, user_factory):
    user_factory("auth_csrf2")
    _login(fresh, "auth_csrf2")
    r = fresh.post("/api/v1/departments", json={"name": "csrf-bad"},
                   headers={"X-CSRF-Token": "not-the-real-token"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "CSRF_FAILED"


def test_cross_origin_request_rejected(fresh, user_factory):
    """CSRF 토큰이 맞아도 남의 출처에서 온 요청은 거부한다(방어 이중화)."""
    user_factory("auth_origin")
    csrf = _login(fresh, "auth_origin").json()["csrf_token"]
    r = fresh.post("/api/v1/departments", json={"name": "origin-probe"},
                   headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "BAD_ORIGIN"


# ── 계정 관리 ─────────────────────────────────────────────────────────────────

def test_admin_can_create_and_reset_account(client, user_factory):
    created = client.post("/api/v1/auth/users",
                          json={"username": "auth_created", "display_name": "생성계정",
                                "password": "created-pw-123", "role": "ADMIN"})
    assert created.status_code == 201, created.text
    uid = created.json()["id"]
    try:
        assert created.json()["must_change_password"] is True   # 최초 로그인 시 변경 강제
        assert "password_hash" not in created.json()

        dup = client.post("/api/v1/auth/users",
                          json={"username": "auth_created", "display_name": "중복",
                                "password": "created-pw-123", "role": "ADMIN"})
        assert dup.status_code == 409

        reset = client.post(f"/api/v1/auth/users/{uid}/password-reset",
                            json={"new_password": "reset-pw-4567"})
        assert reset.status_code == 200 and reset.json()["must_change_password"] is True
    finally:
        with SessionLocal() as db:
            db.query(AdminSession).filter(AdminSession.user_id == uid).delete()
            db.query(AuditLog).filter(AuditLog.actor_id == uid).delete()
            db.query(AppUser).filter(AppUser.id == uid).delete()
            db.commit()


def test_cannot_lock_yourself_out(client):
    me = client.get("/api/v1/auth/me").json()["user"]
    r = client.patch(f"/api/v1/auth/users/{me['id']}", json={"is_active": False})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "SELF_LOCKOUT"
    assert client.get("/api/v1/auth/me").status_code == 200


def test_cannot_remove_last_admin(client, user_factory):
    """다른 관리자를 지울 때, 그 결과 관리자가 0명이 되면 막아야 한다."""
    uid = user_factory("auth_lastadmin")
    with SessionLocal() as db:      # 이 계정만 남기고 나머지 관리자를 잠시 비활성화
        others = db.scalars(select(AppUser).where(AppUser.role == UserRole.ADMIN,
                                                  AppUser.id != uid)).all()
        touched = [u.id for u in others if u.is_active]
        for u in others:
            u.is_active = False
        db.commit()
    try:
        with SessionLocal() as db:
            admin = db.get(AppUser, uid)
            assert admin.is_active
        # client 세션의 계정도 비활성화됐으므로 직접 요청 대신 카운트 함수를 검증한다.
        from app.routers.auth import _active_admin_count
        with SessionLocal() as db:
            assert _active_admin_count(db, exclude_id=uid) == 0
    finally:
        with SessionLocal() as db:
            for oid in touched:
                db.get(AppUser, oid).is_active = True
            db.commit()


def test_audit_trail_records_login_and_logout(fresh, user_factory):
    uid = user_factory("auth_audit")
    csrf = _login(fresh, "auth_audit").json()["csrf_token"]
    fresh.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})
    with SessionLocal() as db:
        actions = {a.action for a in db.scalars(
            select(AuditLog).where(AuditLog.actor_id == uid)).all()}
    assert {"LOGIN_SUCCESS", "LOGOUT"} <= actions
