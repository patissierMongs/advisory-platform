"""관리자 인증 API — 로그인/로그아웃/비밀번호/계정 관리.

라우터 레벨 게이트를 두지 않는다(로그인 자체는 무인증이어야 하므로) — 엔드포인트별로 건다.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import auth
from ..audit import record
from ..core.passwords import check_policy, hash_password, verify_password
from ..db import get_db
from ..enums import UserRole
from ..models import AdminSession, AppUser
from ..schemas import LoginIn, PasswordChangeIn, PasswordResetIn, UserCreateIn, UserPatchIn

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


def _user_item(u: AppUser) -> dict:
    """계정 표현 — 해시는 절대 내보내지 않는다."""
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "role": u.role.value,
        "is_active": u.is_active,
        "must_change_password": bool(u.must_change_password),
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "locked": auth.lockout_remaining(u) > 0,
    }


@router.post("/login")
def login(body: LoginIn, request: Request, response: Response, db: Session = Depends(get_db)):
    user = auth.authenticate(db, body.username.strip(), body.password, request)
    raw, csrf = auth.create_session(db, user, request)
    record(db, action="LOGIN_SUCCESS", actor_id=user.id, entity_type="app_user",
           entity_id=user.id, detail={"username": user.username}, request=request)
    db.commit()
    auth.set_session_cookies(response, raw, csrf)
    return {"user": _user_item(user), "must_change_password": bool(user.must_change_password),
            "csrf_token": csrf}


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response, db: Session = Depends(get_db),
           resolved=Depends(auth.require_session)):
    user, sess = resolved
    auth.revoke_session(db, sess)
    record(db, action="LOGOUT", actor_id=user.id, entity_type="app_user",
           entity_id=user.id, detail=None, request=request)
    db.commit()
    auth.clear_session_cookies(response)
    return None


@router.post("/logout-all")
def logout_all(request: Request, response: Response, db: Session = Depends(get_db),
               resolved=Depends(auth.require_session)):
    user, _ = resolved
    revoked = auth.revoke_all_for_user(db, user.id)
    record(db, action="LOGOUT", actor_id=user.id, entity_type="app_user",
           entity_id=user.id, detail={"revoked": revoked, "all": True}, request=request)
    db.commit()
    auth.clear_session_cookies(response)
    return {"revoked": revoked}


@router.get("/me")
def me(resolved=Depends(auth.require_session)):
    user, sess = resolved
    return {"user": _user_item(user), "must_change_password": bool(user.must_change_password),
            "csrf_token": sess.csrf_token}


@router.post("/password")
def change_password(body: PasswordChangeIn, request: Request, response: Response,
                    db: Session = Depends(get_db), resolved=Depends(auth.require_session)):
    """본인 비밀번호 변경. 강제 변경 상태에서도 호출 가능해야 하므로 require_admin 을 쓰지 않는다."""
    user, sess = resolved
    auth.verify_csrf(request, sess)
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(400, detail={"code": "WRONG_PASSWORD",
                                         "message": "현재 비밀번호가 올바르지 않습니다."})
    try:
        check_policy(body.new_password, user.username)
    except ValueError as e:
        raise HTTPException(400, detail={"code": "WEAK_PASSWORD", "message": str(e)}) from e

    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = auth.now_utc()
    # 비밀번호가 바뀌면 기존 세션은 전부 무효 — 유출된 세션이 살아남지 않게 한다.
    # 호출한 본인은 새 세션으로 갈아끼워 재로그인 없이 이어간다.
    auth.revoke_all_for_user(db, user.id)
    raw, csrf = auth.create_session(db, user, request)
    record(db, action="PASSWORD_CHANGE", actor_id=user.id, entity_type="app_user",
           entity_id=user.id, detail=None, request=request)
    db.commit()
    auth.set_session_cookies(response, raw, csrf)
    return {"ok": True, "csrf_token": csrf}


# ── 계정 관리(관리자 전용) ────────────────────────────────────────────────────

@router.get("/users")
def list_users(db: Session = Depends(get_db), _: AppUser = Depends(auth.require_admin)):
    rows = db.scalars(select(AppUser).order_by(AppUser.username)).all()
    return {"items": [_user_item(u) for u in rows]}


@router.post("/users", status_code=201)
def create_user(body: UserCreateIn, request: Request, db: Session = Depends(get_db),
                _: AppUser = Depends(auth.require_admin)):
    username = body.username.strip()
    if db.scalar(select(AppUser).where(AppUser.username == username)):
        raise HTTPException(409, detail={"code": "DUPLICATE", "message": "이미 존재하는 아이디입니다."})
    try:
        check_policy(body.password, username)
    except ValueError as e:
        raise HTTPException(400, detail={"code": "WEAK_PASSWORD", "message": str(e)}) from e

    user = AppUser(username=username, display_name=body.display_name, role=body.role,
                   is_active=True, password_hash=hash_password(body.password),
                   must_change_password=True)
    db.add(user)
    db.flush()
    record(db, action="USER_CREATE", actor_id=auth.current_actor_id(), entity_type="app_user",
           entity_id=user.id, detail={"username": username, "role": body.role.value},
           request=request)
    db.commit()
    return _user_item(user)


def _active_admin_count(db: Session, *, exclude_id: int | None = None) -> int:
    q = select(AppUser).where(AppUser.role == UserRole.ADMIN, AppUser.is_active.is_(True),
                              AppUser.password_hash.is_not(None))
    if exclude_id is not None:
        q = q.where(AppUser.id != exclude_id)
    return len(db.scalars(q).all())


@router.patch("/users/{user_id}")
def update_user(user_id: int, body: UserPatchIn, request: Request,
                db: Session = Depends(get_db), me: AppUser = Depends(auth.require_admin)):
    user = db.get(AppUser, user_id)
    if user is None:
        raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "계정 없음"})

    disabling = body.is_active is False and user.is_active
    demoting = body.role is not None and body.role != UserRole.ADMIN and user.role == UserRole.ADMIN
    if (disabling or demoting) and user.id == me.id:
        raise HTTPException(409, detail={"code": "SELF_LOCKOUT",
                                         "message": "본인 계정은 비활성화하거나 권한을 낮출 수 없습니다."})
    # 마지막 관리자를 잃으면 아무도 로그인할 수 없는 상태가 된다.
    if (disabling or demoting) and _active_admin_count(db, exclude_id=user.id) == 0:
        raise HTTPException(409, detail={"code": "LAST_ADMIN",
                                         "message": "마지막 관리자 계정입니다. 다른 관리자를 먼저 만드세요."})

    for field in ("display_name", "role", "is_active"):
        value = getattr(body, field)
        if value is not None:
            setattr(user, field, value)
    if disabling or demoting:
        auth.revoke_all_for_user(db, user.id)
    record(db, action="USER_UPDATE", actor_id=me.id, entity_type="app_user",
           entity_id=user.id, detail=body.model_dump(exclude_none=True, mode="json"),
           request=request)
    db.commit()
    return _user_item(user)


@router.post("/users/{user_id}/password-reset")
def reset_password(user_id: int, body: PasswordResetIn, request: Request,
                   db: Session = Depends(get_db), me: AppUser = Depends(auth.require_admin)):
    user = db.get(AppUser, user_id)
    if user is None:
        raise HTTPException(404, detail={"code": "NOT_FOUND", "message": "계정 없음"})
    try:
        check_policy(body.new_password, user.username)
    except ValueError as e:
        raise HTTPException(400, detail={"code": "WEAK_PASSWORD", "message": str(e)}) from e

    user.password_hash = hash_password(body.new_password)
    user.must_change_password = True
    user.failed_count = 0
    user.locked_until = None
    auth.revoke_all_for_user(db, user.id)
    record(db, action="USER_PASSWORD_RESET", actor_id=me.id, entity_type="app_user",
           entity_id=user.id, detail={"username": user.username}, request=request)
    db.commit()
    return _user_item(user)
