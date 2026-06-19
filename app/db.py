"""DB 엔진/세션 — SQLite(기본) 및 PostgreSQL 공용."""
from __future__ import annotations

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


# 신규 컬럼을 기존 SQLite DB 에 무손실 추가(create_all 은 ALTER 안 함). 운영(Postgres)은 정식 마이그레이션 사용.
_ADDED_COLUMNS: dict[str, list[tuple[str, str]]] = {
    "asset": [("owner_team", "VARCHAR(120)"), ("owner_contact", "VARCHAR(120)")],
    "advisory": [("extract_phase", "VARCHAR(20)"), ("error_message", "TEXT"),
                 ("board_published_at", "DATETIME")],
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
