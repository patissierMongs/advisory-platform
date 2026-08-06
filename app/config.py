"""애플리케이션 설정 (환경변수 오버라이드 가능).

폐쇄망/오프라인 운영이 기본 전제이므로 외부 의존이 없는 SQLite를 기본 DB로 사용한다.
운영(PostgreSQL) 전환 시 ADVISORY_DATABASE_URL 만 교체하면 된다(스키마는 SQLAlchemy로 동일).
"""
from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_env_file() -> None:
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_load_env_file()
DATA_DIR = Path(os.environ.get("ADVISORY_DATA_DIR", BASE_DIR / "data"))
UPLOAD_DIR = DATA_DIR / "uploads"
WEB_DIR = BASE_DIR / "web"
# 정적 서빙은 공개 자산만(web/public). 관리자 셸(web/admin)은 세션 확인 라우트로만 나간다.
PUBLIC_WEB_DIR = WEB_DIR / "public"
ADMIN_WEB_DIR = WEB_DIR / "admin"


def _assert_data_dir_not_served() -> None:
    """DATA_DIR 이 web/ 안이면 기동 거부 — 업로드물이 통째로 /ui/ 로 무인증 노출된다.

    경고가 아니라 하드 실패다. 실패 모드(권고문 PDF·증빙 전부 공개 다운로드)가 치명적이고
    조용해서, 켜진 채로 운영되면 알아챌 방법이 없다.
    Windows 파일시스템은 대소문자를 구분하지 않으므로 normcase 로 정규화해 비교한다.
    """
    d, w = DATA_DIR.resolve(), WEB_DIR.resolve()
    if os.path.normcase(str(d)) == os.path.normcase(str(w)) or d.is_relative_to(w):
        raise RuntimeError(
            f"ADVISORY_DATA_DIR({d}) 이 web/({w}) 안에 있습니다 — "
            "업로드 파일이 /ui/ 로 전부 노출됩니다. 앱 폴더 밖 경로로 바꾸세요."
        )


_assert_data_dir_not_served()


def secure_dir(path: Path) -> Path:
    """디렉터리 생성 + 접근 제한.

    POSIX 는 0700. Windows 는 chmod 가 read-only 비트만 건드리는 사실상 no-op 이라
    app/core/winacl.py 가 DATA_DIR 에 건 NTFS ACL 의 (OI)(CI) 상속이 이 역할을 대신한다.
    """
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        try:
            path.chmod(0o700)
        except OSError:
            pass
    return path


def secure_write_bytes(path: Path, data: bytes, *, exclusive: bool = False) -> None:
    """업로드물 저장 — POSIX 에서 umask 와 무관하게 0600 을 보장한다.

    Windows 는 mode 인자를 무시하지만(상위 폴더 ACL 이 담당) O_EXCL 은 유효하다.
    exclusive=True 는 공유 증빙 디렉터리에서 '먼저 만들어 두고 기다리는' 선점 공격을 막는다.
    """
    flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


secure_dir(DATA_DIR)
secure_dir(UPLOAD_DIR)


class Settings:
    # 데이터베이스 — 기본 SQLite(파일). 운영은 postgresql+psycopg://user:pw@host/db
    DATABASE_URL: str = os.environ.get(
        "ADVISORY_DATABASE_URL", f"sqlite:///{(DATA_DIR / 'advisory.db').as_posix()}"
    )

    # 파일 업로드 제약 (§7 비기능)
    MAX_UPLOAD_MB: int = int(os.environ.get("ADVISORY_MAX_UPLOAD_MB", "30"))

    # 알림 채널 (§4.7) — 운영 기본은 WEB_UI + SMTP 메일. 외부 채널 실패는 FAILED 로 기록.
    MESSENGER_ENABLED: bool = os.environ.get("ADVISORY_MESSENGER_ENABLED", "false").lower() == "true"
    MAIL_ENABLED: bool = os.environ.get("ADVISORY_MAIL_ENABLED", "true").lower() == "true"
    GROUPWARE_ENABLED: bool = os.environ.get("ADVISORY_GROUPWARE_ENABLED", "false").lower() == "true"

    # 발신 어댑터 상세 — 활성 시에만 사용. 미설정/실패 시 outbox/board.log 는 참고 로그이며 성공 처리하지 않는다.
    NOTIFY_TIMEOUT_SEC: float = float(os.environ.get("ADVISORY_NOTIFY_TIMEOUT_SEC", "10"))
    # 메일: 표준 SMTP(사내 메일 서버/Exchange). 호스트 미설정 시 FAILED.
    MAIL_SMTP_HOST: str = os.environ.get("ADVISORY_MAIL_SMTP_HOST", "")
    MAIL_SMTP_PORT: int = int(os.environ.get("ADVISORY_MAIL_SMTP_PORT", "25"))
    MAIL_SMTP_USER: str = os.environ.get("ADVISORY_MAIL_SMTP_USER", "")
    MAIL_SMTP_PASSWORD: str = os.environ.get("ADVISORY_MAIL_SMTP_PASSWORD", "")
    MAIL_USE_TLS: bool = os.environ.get("ADVISORY_MAIL_USE_TLS", "false").lower() == "true"
    MAIL_FROM: str = os.environ.get("ADVISORY_MAIL_FROM", "")
    # 메신저/그룹웨어: 범용 웹훅 POST(JSON). URL 미설정 시 outbox/board.log.
    MESSENGER_WEBHOOK_URL: str = os.environ.get("ADVISORY_MESSENGER_WEBHOOK_URL", "")
    GROUPWARE_WEBHOOK_URL: str = os.environ.get("ADVISORY_GROUPWARE_WEBHOOK_URL", "")

    # CORS — 기본은 '동일 출처만'(빈 목록 → CORSMiddleware 자체를 붙이지 않음).
    # 쿠키 세션을 쓰므로 와일드카드는 허용하지 않는다(allow_credentials 와 공존 불가).
    CORS_ORIGINS: list[str] = [
        o.strip()
        for o in os.environ.get("ADVISORY_CORS_ORIGINS", "").split(",")
        if o.strip()
    ]

    # ── 인증/세션 (§관리자 로그인) ──
    # 세션 쿠키 Secure 플래그. 폐쇄망 HTTP 배포가 기본이라 false; HTTPS 종단 시 true 로.
    SESSION_COOKIE_SECURE: bool = (
        os.environ.get("ADVISORY_SESSION_COOKIE_SECURE", "false").lower() == "true")
    SESSION_HOURS: int = int(os.environ.get("ADVISORY_SESSION_HOURS", "12"))
    SESSION_IDLE_MINUTES: int = int(os.environ.get("ADVISORY_SESSION_IDLE_MINUTES", "60"))
    LOGIN_MAX_FAILS: int = int(os.environ.get("ADVISORY_LOGIN_MAX_FAILS", "5"))
    LOGIN_LOCKOUT_MINUTES: int = int(os.environ.get("ADVISORY_LOGIN_LOCKOUT_MINUTES", "15"))
    # 최초 기동 시 관리자 부트스트랩. 비밀번호 미설정이면 무작위 생성 후 콘솔에 1회 출력
    # (코드베이스에 기본 비밀번호를 두지 않는다). 최초 로그인 시 변경이 강제된다.
    BOOTSTRAP_ADMIN: str = os.environ.get("ADVISORY_BOOTSTRAP_ADMIN", "admin")
    BOOTSTRAP_PASSWORD: str = os.environ.get("ADVISORY_BOOTSTRAP_PASSWORD", "")
    # 그룹웨어 ack 웹훅 HMAC 시크릿. 미설정이면 해당 엔드포인트는 503(fail closed).
    WEBHOOK_SECRET: str = os.environ.get("ADVISORY_WEBHOOK_SECRET", "")

    # 시작 시 프로토타입 데이터 시드 여부(데모/개발용).
    SEED_ON_START: bool = os.environ.get("ADVISORY_SEED", "false").lower() == "true"
    # 최초 부팅 시 동봉 CVE 피드(samples/cve_feeds/) 자동 적재 여부(폐쇄망 즉시 사용).
    LOAD_BUNDLED_FEEDS: bool = os.environ.get("ADVISORY_BUNDLED_FEEDS", "false").lower() == "true"

    @property
    def max_upload_bytes(self) -> int:
        return self.MAX_UPLOAD_MB * 1024 * 1024


settings = Settings()

if "*" in settings.CORS_ORIGINS:
    # 와일드카드 + 자격증명 쿠키는 CORS 스펙상 불가이며, 허용되면 모든 사이트가
    # 사용자의 관리자 세션으로 API 를 호출할 수 있게 된다.
    raise RuntimeError(
        "ADVISORY_CORS_ORIGINS 에 '*' 는 사용할 수 없습니다(쿠키 인증과 공존 불가). "
        ".env 에서 출처를 명시하거나 값을 비워 동일 출처 전용으로 두세요."
    )
