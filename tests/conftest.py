"""테스트 공용 픽스처.

앱 import 이전에 환경변수를 고정해야 한다(config 가 import 시점에 env 를 읽음).
번들 CVE 피드 자동적재는 sentinel 선생성으로 스킵(격리·속도).
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="advtest_")
os.environ["ADVISORY_DATABASE_URL"] = f"sqlite:///{Path(_TMP, 'test.db').as_posix()}"
os.environ["ADVISORY_DATA_DIR"] = _TMP
os.environ["ADVISORY_SEED"] = "false"           # 데모 시드 비활성 → 깨끗한 DB
os.environ["ADVISORY_BUNDLED_FEEDS"] = "false"  # 번들 CVE 피드 자동적재 비활성
os.environ["ADVISORY_WEBHOOK_SECRET"] = "test-webhook-secret"
os.environ["ADVISORY_CORS_ORIGINS"] = ""        # 동일 출처 전용(쿠키 인증)
os.environ["ADVISORY_BOOTSTRAP_ADMIN"] = "testadmin"
os.environ["ADVISORY_BOOTSTRAP_PASSWORD"] = "test-admin-pw-1"

import hashlib  # noqa: E402
import hmac  # noqa: E402
import json  # noqa: E402
import time  # noqa: E402

import pytest  # noqa: E402


def signed_webhook_post(client, path: str, payload: dict):
    """HMAC 서명된 웹훅 POST — 서명 대상이 raw body 라 json= 대신 content= 로 보낸다."""
    body = json.dumps(payload).encode("utf-8")
    ts = str(int(time.time()))
    sig = hmac.new(os.environ["ADVISORY_WEBHOOK_SECRET"].encode(),
                   f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return client.post(path, content=body, headers={
        "Content-Type": "application/json",
        "X-Advisory-Timestamp": ts,
        "X-Advisory-Signature": f"sha256={sig}",
    })


@pytest.fixture(scope="session", autouse=True)
def _init_db():
    from app.db import init_db
    init_db()


@pytest.fixture(autouse=True)
def _clean_tables():
    """각 테스트 전 cve/cve_feed_import 를 비워 격리. (FK: cve → cve_feed_import 자식 먼저)

    app_user / admin_session 은 절대 건드리지 않는다 — 지우면 세션 스코프 client 가
    로그아웃돼 이후 전 테스트가 401 로 무너진다.
    """
    from sqlalchemy import delete

    from app.db import SessionLocal
    from app.models import Cve, CveFeedImport
    with SessionLocal() as db:
        db.execute(delete(Cve))
        db.execute(delete(CveFeedImport))
        db.commit()
    yield


ADMIN_USERNAME = "testadmin"
ADMIN_PASSWORD = "test-admin-pw-1"


def _ensure_admin() -> None:
    """부트스트랩 관리자의 강제 비밀번호 변경을 해제한다.

    부트스트랩은 must_change_password=True 로 계정을 만든다(운영에서는 그래야 한다).
    테스트는 매번 변경 절차를 밟을 이유가 없으므로 플래그만 내려 준다.
    """
    from sqlalchemy import select

    from app.db import SessionLocal
    from app.models import AppUser
    with SessionLocal() as db:
        user = db.scalar(select(AppUser).where(AppUser.username == ADMIN_USERNAME))
        assert user is not None, "부트스트랩 관리자가 생성되지 않았다"
        user.must_change_password = False
        db.commit()


@pytest.fixture(scope="session")
def client():
    """관리자로 로그인된 클라이언트.

    기존 테스트 대부분이 관리자 API 를 두드리므로, 익명 클라이언트를 기본으로 두면
    ~200개 호출부를 전부 고쳐야 한다. 반대로 두면(로그인된 client + 별도 public_client)
    공개 게시판 엔드포인트는 세션이 있어도 그대로 동작하므로 기존 파일이 거의 그대로 통과한다.

    CSRF 토큰을 기본 헤더로 심는다 — httpx TestClient 는 인스턴스 기본 헤더를 매 요청에
    병합하므로 개별 post/patch/delete 호출을 손대지 않아도 된다.
    """
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        _ensure_admin()
        r = c.post("/api/v1/auth/login",
                   json={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD})
        assert r.status_code == 200, r.text
        c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
        yield c


@pytest.fixture(scope="session")
def public_client():
    """로그인하지 않은 클라이언트 — 익명 접근이 실제로 막히는지 확인할 때 쓴다."""
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        yield c
