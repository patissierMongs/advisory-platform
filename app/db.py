"""DB 엔진/세션 — SQLite(기본) 및 PostgreSQL 공용."""
from __future__ import annotations

import os
from collections.abc import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings

_is_sqlite = settings.DATABASE_URL.startswith("sqlite")

engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    future=True,
    connect_args={"check_same_thread": False} if _is_sqlite else {},
)

if _is_sqlite:
    # 외래키 제약 강제(SQLite 기본 비활성) + 동시성 개선.
    @event.listens_for(engine, "connect")
    def _sqlite_pragmas(dbapi_conn, _record):  # noqa: ANN001
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        # 쓰기 잠금 대기(기본 5s → 15s) — 피드 재작업 등 긴 쓰기와 겹칠 때
        # 'database is locked' 500 대신 대기 후 진행(§적대검증 확정).
        cur.execute("PRAGMA busy_timeout=15000")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


class Base(DeclarativeBase):
    pass


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """모든 테이블 생성(idempotent)."""
    from . import models  # noqa: F401  — 모델 등록

    Base.metadata.create_all(bind=engine)
    _ensure_sqlite_columns()
    _restrict_sqlite_file()


def _restrict_sqlite_file() -> None:
    """DB 파일(+WAL/SHM)을 소유자 전용으로. Windows 는 DATA_DIR 의 NTFS ACL 상속이 담당한다."""
    if not _is_sqlite or os.name != "posix":
        return
    path = settings.DATABASE_URL.split("sqlite:///", 1)[-1]
    if not path or path == ":memory:":
        return
    for suffix in ("", "-wal", "-shm"):
        try:
            os.chmod(path + suffix, 0o600)
        except OSError:
            pass  # 아직 없거나(WAL 미생성) 권한 부족 — 치명적이지 않다


# 신규 컬럼을 기존 SQLite DB 에 무손실 추가(create_all 은 ALTER 안 함). 운영(Postgres)은 정식 마이그레이션 사용.
_ADDED_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "asset": [("owner_team", "VARCHAR(120)"), ("owner_contact", "VARCHAR(120)")],
    "advisory": [("extract_phase", "VARCHAR(20)"), ("error_message", "TEXT"),
                 ("board_published_at", "DATETIME"),
                 ("due_source", "VARCHAR(10)"), ("channel_source", "VARCHAR(10)")],
    "advisory_comment": [("evidence_path", "TEXT"), ("evidence_name", "VARCHAR(200)")],
    "match": [("ack_status", "VARCHAR(20) DEFAULT 'NONE' NOT NULL"), ("ack_by", "VARCHAR(80)"),
              ("ack_note", "TEXT"), ("ack_at", "DATETIME")],
    # §개편 — 추출 엔진·다중 제품
    "advisory_cve": [("is_deleted", "BOOLEAN DEFAULT 0 NOT NULL")],
    "cve": [("affected_products", "JSON")],
    # §개편 후속 — 피드 적용 실패 사유 기록(이력 오표시 방지)
    "cve_feed_import": [("error_message", "TEXT")],
    # §관리자 로그인 — 자격증명. SQLite 는 리터럴 기본값 없는 NOT NULL 을 ADD COLUMN 못 한다.
    "app_user": [("password_hash", "TEXT"),
                 ("must_change_password", "BOOLEAN DEFAULT 0 NOT NULL"),
                 ("failed_count", "INTEGER DEFAULT 0 NOT NULL"),
                 ("locked_until", "DATETIME"),
                 ("last_login_at", "DATETIME"),
                 ("password_changed_at", "DATETIME")],
}


def _ensure_sqlite_columns() -> None:
    if not _is_sqlite:
        return
    with engine.begin() as conn:
        for table, cols in _ADDED_COLUMNS.items():
            existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})")}
            if not existing:
                continue  # 테이블 미존재(create_all 이 신스키마로 생성했으면 컬럼 포함)
            for name, ddl in cols:
                if name not in existing:
                    conn.exec_driver_sql(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")
