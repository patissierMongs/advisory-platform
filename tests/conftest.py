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
    """각 테스트 전 cve/cve_feed_import 를 비워 격리. (FK: cve → cve_feed_import 자식 먼저)"""
    from sqlalchemy import delete

    from app.db import SessionLocal
    from app.models import Cve, CveFeedImport
    with SessionLocal() as db:
        db.execute(delete(Cve))
        db.execute(delete(CveFeedImport))
        db.commit()
    yield


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="session")
def public_client():
    """로그인하지 않은 클라이언트 — 익명 접근이 실제로 막히는지 확인할 때 쓴다."""
    from fastapi.testclient import TestClient

    from app.main import app
    with TestClient(app) as c:
        yield c
