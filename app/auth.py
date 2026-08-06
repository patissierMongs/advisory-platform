"""관리자 인증 — 서버측 세션 + 불투명 쿠키 (표준 라이브러리만).

설계
  · 게시판(/api/v1/board/*)은 사내 무인증 공개를 유지한다. 인증은 관리자 표면에만 건다.
  · 세션 상태는 DB(admin_session)에 둔다. 쿠키에는 불투명 토큰만 싣고 DB 에는 그 sha256 만
    저장해, DB 파일이 유출돼도 살아있는 세션을 되살릴 수 없게 한다.
  · CSRF 는 전역 미들웨어가 아니라 이 모듈의 인증 의존성 안에서 검사한다. 세션 없는
    익명 게시판 POST 는 검사 대상이 아니므로 board.html 을 건드리지 않아도 된다.
  · 의존성은 전부 async — sync 의존성은 threadpool 에서 돌아 ContextVar 설정이
    요청 컨텍스트로 전파되지 않는다(감사 actor 연결이 조용히 깨진다).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from collections.abc import AsyncGenerator
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .audit import record
from .config import settings
from .core.passwords import DUMMY_HASH, hash_password, needs_rehash, verify_password
from .db import get_db
from .enums import UserRole
from .models import AdminSession, AppUser

SESSION_COOKIE = "adv_session"
CSRF_COOKIE = "adv_csrf"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# 강제 비밀번호 변경 중에도 허용되는 자기 관리 경로(그 외 관리자 API 는 전부 403).
PASSWORD_CHANGE_EXEMPT = frozenset({"/api/v1/auth/me", "/api/v1/auth/password",
                                    "/api/v1/auth/logout", "/api/v1/auth/logout-all"})

# 감사 로그 행위주체. get_actor_id(db) 가 이 값을 읽어 25개 호출부를 손대지 않는다.
_ACTOR: ContextVar[int | None] = ContextVar("advisory_actor_id", default=None)


def current_actor_id() -> int | None:
    return _ACTOR.get()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime | None) -> datetime | None:
    """SQLite 는 tz 를 잃어버리고 돌아온다 — 비교 전에 UTC 로 되붙인다."""
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ── 세션 수명주기 ─────────────────────────────────────────────────────────────

def create_session(db: Session, user: AppUser, request: Request) -> tuple[str, str]:
    """세션 행 생성 후 (쿠키에 실을 원본 토큰, csrf 토큰) 반환."""
    raw = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    now = now_utc()
    db.add(AdminSession(
        user_id=user.id,
        token_hash=_token_hash(raw),
        csrf_token=csrf,
        expires_at=now + timedelta(hours=settings.SESSION_HOURS),
        last_seen_at=now,
        ip=getattr(getattr(request, "client", None), "host", None),
        user_agent=(request.headers.get("user-agent") or "")[:400] or None,
    ))
    return raw, csrf


def revoke_session(db: Session, sess: AdminSession) -> None:
    sess.revoked_at = now_utc()


def revoke_all_for_user(db: Session, user_id: int, *, except_id: int | None = None) -> int:
    rows = db.scalars(
        select(AdminSession).where(AdminSession.user_id == user_id,
                                   AdminSession.revoked_at.is_(None))
    ).all()
    now = now_utc()
    count = 0
    for s in rows:
        if except_id is not None and s.id == except_id:
            continue
        s.revoked_at = now
        count += 1
    return count


def purge_expired(db: Session) -> int:
    """만료 후 7일 지난 세션 행 정리(기동 시 1회). 감사용으로 잠시 남겨 둔다."""
    cutoff = now_utc() - timedelta(days=7)
    rows = db.scalars(select(AdminSession).where(AdminSession.expires_at < cutoff)).all()
    for s in rows:
        db.delete(s)
    return len(rows)


def set_session_cookies(response: Response, raw_token: str, csrf: str) -> None:
    max_age = settings.SESSION_HOURS * 3600
    response.set_cookie(SESSION_COOKIE, raw_token, max_age=max_age, path="/",
                        httponly=True, samesite="strict",
                        secure=settings.SESSION_COOKIE_SECURE)
    # CSRF 쿠키는 SPA 가 읽어 헤더로 되돌려야 하므로 HttpOnly 가 아니다.
    # 값 자체는 세션 행과 대조하므로 읽히는 것만으로는 위조에 쓸 수 없다.
    response.set_cookie(CSRF_COOKIE, csrf, max_age=max_age, path="/",
                        httponly=False, samesite="strict",
                        secure=settings.SESSION_COOKIE_SECURE)


def clear_session_cookies(response: Response) -> None:
    for name in (SESSION_COOKIE, CSRF_COOKIE):
        response.delete_cookie(name, path="/", samesite="strict",
                               secure=settings.SESSION_COOKIE_SECURE)


def resolve_session(db: Session, request: Request) -> tuple[AppUser, AdminSession] | None:
    """쿠키 → 세션 행 → 사용자. 만료·폐기·비활성은 전부 None."""
    raw = request.cookies.get(SESSION_COOKIE)
    if not raw:
        return None
    sess = db.scalar(select(AdminSession).where(AdminSession.token_hash == _token_hash(raw)))
    if sess is None or sess.revoked_at is not None:
        return None
    now = now_utc()
    if _aware(sess.expires_at) <= now:
        return None
    idle_limit = timedelta(minutes=settings.SESSION_IDLE_MINUTES)
    last_seen = _aware(sess.last_seen_at)
    if now - last_seen > idle_limit:
        sess.revoked_at = now
        db.commit()
        return None
    user = db.get(AppUser, sess.user_id)
    if user is None or not user.is_active:
        return None
    # 요청마다 쓰면 SQLite(WAL, busy_timeout=15s) 에서 병목이 된다 — 60초 이상 낡았을 때만.
    if now - last_seen > timedelta(seconds=60):
        sess.last_seen_at = now
        db.commit()
    return user, sess


# ── 로그인 시도 제한 ───────────────────────────────────────────────────────────

# IP 당 거친 스로틀. 단일 uvicorn 프로세스 전제라 프로세스 메모리에 두며 재시작 시 리셋된다
# (계정 잠금이 주 방어선이고 이건 분산 추측 시도를 늦추는 보조 수단이다).
_IP_FAILS: dict[str, list[float]] = {}
_IP_WINDOW_SEC = 300
_IP_MAX_FAILS = 20


def _client_ip(request: Request) -> str:
    return getattr(getattr(request, "client", None), "host", None) or "-"


def ip_throttled(request: Request) -> bool:
    now = time.monotonic()
    hits = [t for t in _IP_FAILS.get(_client_ip(request), []) if now - t < _IP_WINDOW_SEC]
    _IP_FAILS[_client_ip(request)] = hits
    return len(hits) >= _IP_MAX_FAILS


def note_ip_failure(request: Request) -> None:
    _IP_FAILS.setdefault(_client_ip(request), []).append(time.monotonic())


def reset_ip_failures(request: Request) -> None:
    _IP_FAILS.pop(_client_ip(request), None)


def lockout_remaining(user: AppUser) -> int:
    until = _aware(user.locked_until)
    if until is None:
        return 0
    return max(0, int((until - now_utc()).total_seconds()))


def authenticate(db: Session, username: str, password: str,
                 request: Request) -> AppUser:
    """성공 시 사용자, 실패 시 HTTPException. 계정 존재 여부를 응답으로 흘리지 않는다."""
    if ip_throttled(request):
        raise HTTPException(429, detail={"code": "TOO_MANY_ATTEMPTS",
                                         "message": "로그인 시도가 너무 많습니다. 잠시 후 다시 시도하세요."})

    user = db.scalar(select(AppUser).where(AppUser.username == username))

    # 잠금 중이면 비밀번호를 확인조차 하지 않는다(잠금 중 정답 입력으로 잠금이 풀리면 의미가 없다).
    if user is not None and lockout_remaining(user) > 0:
        record(db, action="LOGIN_LOCKED", actor_id=user.id, entity_type="app_user",
               entity_id=user.id, detail={"username": username[:80]}, request=request)
        db.commit()
        raise HTTPException(423, detail={
            "code": "ACCOUNT_LOCKED",
            "message": "계정이 잠겼습니다. 잠시 후 다시 시도하세요.",
            "retry_after_seconds": lockout_remaining(user),
        })

    # 없는 사용자에도 동일한 연산량을 태워 타이밍으로 계정 존재 여부가 새지 않게 한다.
    stored = user.password_hash if user is not None else None
    ok = verify_password(password, stored or DUMMY_HASH)
    if user is None or not user.is_active or not stored or not ok:
        if user is not None:
            user.failed_count = (user.failed_count or 0) + 1
            if user.failed_count >= settings.LOGIN_MAX_FAILS:
                user.locked_until = now_utc() + timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
                user.failed_count = 0
        note_ip_failure(request)
        record(db, action="LOGIN_FAILURE", actor_id=user.id if user else None,
               entity_type="app_user", entity_id=user.id if user else None,
               detail={"username": username[:80]}, request=request)
        db.commit()   # 실패 카운터가 남아야 잠금이 동작한다
        raise HTTPException(401, detail={"code": "INVALID_CREDENTIALS",
                                         "message": "아이디 또는 비밀번호가 올바르지 않습니다."})

    user.failed_count = 0
    user.locked_until = None
    user.last_login_at = now_utc()
    if needs_rehash(stored):
        user.password_hash = hash_password(password)
    reset_ip_failures(request)
    return user


# ── CSRF ──────────────────────────────────────────────────────────────────────

def _same_origin(request: Request, origin: str) -> bool:
    parts = urlsplit(origin)
    host = request.headers.get("host") or ""
    return f"{parts.hostname}:{parts.port}" == host or (parts.hostname or "") == host.split(":")[0]


def verify_csrf(request: Request, sess: AdminSession) -> None:
    if request.method in SAFE_METHODS:
        return
    sent = request.headers.get(CSRF_HEADER) or ""
    # 쿠키가 아니라 세션 행의 값과 대조한다 — 단순 double-submit 과 달리 형제 호스트에서
    # 쿠키를 주입해도 위조할 수 없다.
    if not sent or not hmac.compare_digest(sent, sess.csrf_token):
        raise HTTPException(403, detail={"code": "CSRF_FAILED",
                                         "message": "요청 검증에 실패했습니다. 새로고침 후 다시 시도하세요."})
    origin = request.headers.get("origin")
    if origin and not _same_origin(request, origin) and origin not in settings.CORS_ORIGINS:
        raise HTTPException(403, detail={"code": "BAD_ORIGIN",
                                         "message": "허용되지 않은 출처의 요청입니다."})


# ── 의존성 ────────────────────────────────────────────────────────────────────

async def get_current_user(
    request: Request, db: Session = Depends(get_db),
) -> AsyncGenerator[tuple[AppUser, AdminSession] | None, None]:
    """세션을 해석하고 감사 actor ContextVar 를 설정한다(익명이면 None).

    yield 의존성이라 요청이 끝나면 ContextVar 를 반드시 되돌린다 — 워커 스레드가 재사용될 때
    앞 요청의 주체가 남아 엉뚱한 사용자로 감사 로그가 찍히는 것을 막는다.
    """
    resolved = resolve_session(db, request)
    token = _ACTOR.set(resolved[0].id if resolved else None)
    try:
        yield resolved
    finally:
        _ACTOR.reset(token)


async def require_session(
    resolved: tuple[AppUser, AdminSession] | None = Depends(get_current_user),
) -> tuple[AppUser, AdminSession]:
    if resolved is None:
        raise HTTPException(401, detail={"code": "AUTH_REQUIRED", "message": "로그인이 필요합니다."})
    return resolved


async def require_admin_no_pwcheck(
    request: Request,
    resolved: tuple[AppUser, AdminSession] = Depends(require_session),
) -> AppUser:
    user, sess = resolved
    if user.role != UserRole.ADMIN:
        raise HTTPException(403, detail={"code": "FORBIDDEN", "message": "관리자 권한이 필요합니다."})
    verify_csrf(request, sess)
    return user


async def require_admin(
    request: Request, user: AppUser = Depends(require_admin_no_pwcheck),
) -> AppUser:
    """관리자 라우터 게이트 — APIRouter(dependencies=[Depends(require_admin)]) 로 쓴다.

    강제 변경 상태에서는 자기 관리 경로 외 전부 403. 401 이 아니라 403 이어야
    프론트가 '로그인 필요' 와 '비밀번호 변경 필요' 를 구분해 다른 화면으로 보낼 수 있다.
    """
    if user.must_change_password and request.url.path not in PASSWORD_CHANGE_EXEMPT:
        raise HTTPException(403, detail={
            "code": "PASSWORD_CHANGE_REQUIRED",
            "message": "최초 로그인입니다. 비밀번호를 변경해야 계속할 수 있습니다.",
        })
    return user


# ── 부트스트랩 ────────────────────────────────────────────────────────────────

def ensure_bootstrap_admin(db: Session) -> None:
    """로그인 가능한 관리자가 하나도 없으면 1명 생성(멱등).

    비밀번호가 env 에 없으면 무작위 생성해 콘솔에 1회만 출력한다 — 코드베이스에 기본
    비밀번호를 두지 않기 위해서다. Windows 는 start.bat 창이 열린 채 유지되므로 운영자가
    바로 확인할 수 있다. 어느 경로든 최초 로그인 시 변경이 강제된다.
    """
    existing = db.scalar(
        select(AppUser).where(AppUser.role == UserRole.ADMIN,
                              AppUser.password_hash.is_not(None)).limit(1))
    if existing is not None:
        return

    username = (settings.BOOTSTRAP_ADMIN or "admin").strip()
    password = settings.BOOTSTRAP_PASSWORD
    generated = not password
    if generated:
        password = secrets.token_urlsafe(12)

    user = db.scalar(select(AppUser).where(AppUser.username == username))
    if user is None:
        user = AppUser(username=username, display_name="관리자", role=UserRole.ADMIN)
        db.add(user)
    user.role = UserRole.ADMIN
    user.is_active = True
    user.password_hash = hash_password(password)
    user.must_change_password = True
    user.failed_count = 0
    user.locked_until = None
    db.commit()

    print(f"[auth] 초기 관리자 계정 생성: {username}", flush=True)
    if generated:
        print(f"[auth] 초기 비밀번호(이 화면에만 1회 표시): {password}", flush=True)
    print("[auth] 최초 로그인 시 비밀번호 변경이 강제됩니다.", flush=True)
