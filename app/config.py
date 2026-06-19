"""애플리케이션 설정 (환경변수 오버라이드 가능).

폐쇄망/오프라인 운영이 기본 전제이므로 외부 의존이 없는 SQLite를 기본 DB로 사용한다.
운영(PostgreSQL) 전환 시 ADVISORY_DATABASE_URL 만 교체하면 된다(스키마는 SQLAlchemy로 동일).
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("ADVISORY_DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
WEB_DIR = BASE_DIR / "web"

DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


class Settings:
    # 데이터베이스 — 기본 SQLite(파일). 운영은 postgresql+psycopg://user:pw@host/db
    DATABASE_URL: str = os.environ.get(
        "ADVISORY_DATABASE_URL", f"sqlite:///{(DATA_DIR / 'advisory.db').as_posix()}"
    )

    # 파일 업로드 제약 (§7 비기능)
    MAX_UPLOAD_MB: int = int(os.environ.get("ADVISORY_MAX_UPLOAD_MB", "30"))

    # 알림 채널 (§4.7) — 폐쇄망 기본은 WEB_UI + 파일 로그. 메신저/메일은 게이트웨이 확정 시 활성.
    MESSENGER_ENABLED: bool = os.environ.get("ADVISORY_MESSENGER_ENABLED", "false").lower() == "true"
    MAIL_ENABLED: bool = os.environ.get("ADVISORY_MAIL_ENABLED", "false").lower() == "true"
    GROUPWARE_ENABLED: bool = os.environ.get("ADVISORY_GROUPWARE_ENABLED", "false").lower() == "true"

    # 발신 어댑터 상세 — 활성 시에만 사용. 미설정/실패 시 outbox/board.log 폴백(폐쇄망 기본 외부호출 0 유지).
    NOTIFY_TIMEOUT_SEC: float = float(os.environ.get("ADVISORY_NOTIFY_TIMEOUT_SEC", "10"))
    # 메일: 표준 SMTP(사내 메일 서버/Exchange). 호스트 미설정 시 outbox.
    MAIL_SMTP_HOST: str = os.environ.get("ADVISORY_MAIL_SMTP_HOST", "")
    MAIL_SMTP_PORT: int = int(os.environ.get("ADVISORY_MAIL_SMTP_PORT", "25"))
    MAIL_SMTP_USER: str = os.environ.get("ADVISORY_MAIL_SMTP_USER", "")
    MAIL_SMTP_PASSWORD: str = os.environ.get("ADVISORY_MAIL_SMTP_PASSWORD", "")
    MAIL_USE_TLS: bool = os.environ.get("ADVISORY_MAIL_USE_TLS", "false").lower() == "true"
    MAIL_FROM: str = os.environ.get("ADVISORY_MAIL_FROM", "")
    # 메신저/그룹웨어: 범용 웹훅 POST(JSON). URL 미설정 시 outbox/board.log.
    MESSENGER_WEBHOOK_URL: str = os.environ.get("ADVISORY_MESSENGER_WEBHOOK_URL", "")
    GROUPWARE_WEBHOOK_URL: str = os.environ.get("ADVISORY_GROUPWARE_WEBHOOK_URL", "")

    # CORS — 단일 SPA가 동일 출처에서 서빙되면 불필요하나, 분리 개발을 위해 허용.
    CORS_ORIGINS: list[str] = [
        o.strip()
        for o in os.environ.get("ADVISORY_CORS_ORIGINS", "*").split(",")
        if o.strip()
    ]

    # 시작 시 프로토타입 데이터 시드 여부(데모/개발용).
    SEED_ON_START: bool = os.environ.get("ADVISORY_SEED", "true").lower() == "true"
    # 최초 부팅 시 동봉 CVE 피드(samples/cve_feeds/) 자동 적재 여부(폐쇄망 즉시 사용).
    LOAD_BUNDLED_FEEDS: bool = os.environ.get("ADVISORY_BUNDLED_FEEDS", "true").lower() == "true"

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_MB * 1024 * 1024


settings = Settings()
