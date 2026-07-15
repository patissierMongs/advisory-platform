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

import pytest  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _init_db():
    from app.db import init_db
    init_db()


@pytest.fixture(autouse=True)
def _clean_tables():
    """각 테스트 전 cve/cve_feed_import 를 비워 격리. (FK: cve → cve_feed_import 자식 먼저)

    advisory_cve.cve_ref_id 가 cve 를 참조할 수 있어(게이트 수동 등록·피드 재평가)
    삭제 전 참조를 끊는다 — 링크만 초기화, 추출 CVE 행 자체는 보존.
    """
    from sqlalchemy import delete, update

    from app.db import SessionLocal
    from app.models import AdvisoryCve, Cve, CveFeedImport
    with SessionLocal() as db:
        db.execute(update(AdvisoryCve).values(cve_ref_id=None))
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
