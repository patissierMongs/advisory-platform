"""SQLAlchemy 모델 — 명세서 §3 데이터 모델.

이식성을 위해 enum 은 native_enum=False(VARCHAR+CHECK), JSONB 는 JSON 으로 표현한다.
PostgreSQL 운영 시 JSON→JSONB, DateTime(timezone)→TIMESTAMPTZ 로 자연 매핑된다.
"""
from __future__ import annotations

from datetime import date, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from . import enums
from .db import Base


def _enum(e):
    # 이식 가능한 문자열 enum(길이 32 VARCHAR + CHECK).
    return Enum(e, native_enum=False, length=32, validate_strings=True)


class TimestampMixin:
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), onupdate=func.now(), nullable=True
    )


class AppUser(TimestampMixin, Base):
    __tablename__ = "app_user"
    username: Mapped[str] = mapped_column(String(80), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    role: Mapped[enums.UserRole] = mapped_column(
        _enum(enums.UserRole), default=enums.UserRole.ANALYST, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Department(TimestampMixin, Base):
    __tablename__ = "department"
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    code: Mapped[str | None] = mapped_column(String(40))
    messenger_id: Mapped[str | None] = mapped_column(String(120))
    email: Mapped[str | None] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    assets: Mapped[list["Asset"]] = relationship(back_populates="department")


class AssetImport(TimestampMixin, Base):
    __tablename__ = "asset_import"
    file_name: Mapped[str] = mapped_column(String(200), nullable=False)
    sheet_name: Mapped[str | None] = mapped_column(String(120))
    mapping: Mapped[dict | None] = mapped_column(JSON)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[enums.AssetImportStatus] = mapped_column(
        _enum(enums.AssetImportStatus), default=enums.AssetImportStatus.PREVIEW, nullable=False
    )
    file_path: Mapped[str | None] = mapped_column(Text)


class AssetImportMapping(TimestampMixin, Base):
    """매핑 프리셋(선택) — 동일 양식 재업로드 시 자동 적용."""
    __tablename__ = "asset_import_mapping"
    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    mapping: Mapped[dict] = mapped_column(JSON, nullable=False)


class Asset(TimestampMixin, Base):
    __tablename__ = "asset"
    asset_no: Mapped[str] = mapped_column(String(60), unique=True, nullable=False)
    department_id: Mapped[int] = mapped_column(ForeignKey("department.id"), nullable=False)
    product_raw: Mapped[str | None] = mapped_column(String(200))
    product_key: Mapped[str] = mapped_column(String(80), nullable=False)
    version_raw: Mapped[str | None] = mapped_column(String(120))
    version_norm: Mapped[str | None] = mapped_column(String(120))
    ip: Mapped[str | None] = mapped_column(String(45))
    owner_name: Mapped[str | None] = mapped_column(String(80))
    owner_team: Mapped[str | None] = mapped_column(String(120))    # 담당 셀 분리(소속/팀)
    owner_contact: Mapped[str | None] = mapped_column(String(120))  # 담당 셀 분리(연락처)
    status: Mapped[enums.AssetStatus] = mapped_column(
        _enum(enums.AssetStatus), default=enums.AssetStatus.NORMAL, nullable=False
    )
    import_batch_id: Mapped[int | None] = mapped_column(ForeignKey("asset_import.id"))
    extra: Mapped[dict | None] = mapped_column(JSON)

    department: Mapped[Department] = relationship(back_populates="assets")

    __table_args__ = (
        Index("ix_asset_match", "product_key", "version_norm"),
    )


class Cve(TimestampMixin, Base):
    __tablename__ = "cve"
    cve_id: Mapped[str] = mapped_column(String(24), unique=True, nullable=False, index=True)
    product_name: Mapped[str | None] = mapped_column(String(200))
    product_key: Mapped[str | None] = mapped_column(String(80), index=True)
    # 영향 버전 규칙(§4.6): ["22H2","23H2"] | {"lt":"124"} | {"range":[a,b]} | "*"
    affected_versions: Mapped[object | None] = mapped_column(JSON)
    # 다중 제품 지원(§개편) — 한 CVE 가 여러 제품에 영향을 줄 때(primary 외 추가분):
    # [{"product_name":..,"product_key":..,"affected_versions":..}, ...]
    affected_products: Mapped[list | None] = mapped_column(JSON)
    cpe_list: Mapped[list | None] = mapped_column(JSON)
    severity: Mapped[enums.Severity] = mapped_column(
        _enum(enums.Severity), default=enums.Severity.MEDIUM, nullable=False
    )
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    description: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[date | None] = mapped_column(Date)
    source: Mapped[str | None] = mapped_column(String(40))
    feed_import_id: Mapped[int | None] = mapped_column(ForeignKey("cve_feed_import.id"))


class Advisory(TimestampMixin, Base):
    __tablename__ = "advisory"
    doc_no: Mapped[str | None] = mapped_column(String(120))
    title: Mapped[str | None] = mapped_column(String(400))
    source_org: Mapped[str | None] = mapped_column(String(80))
    receive_channel: Mapped[enums.ReceiveChannel | None] = mapped_column(_enum(enums.ReceiveChannel))
    received_at: Mapped[date | None] = mapped_column(Date)
    due_at: Mapped[date | None] = mapped_column(Date)
    # 조치기한·접수경로 출처: 'PDF'(본문 추출) | 'MANUAL'(관리자 지정) | None(미지정)
    due_source: Mapped[str | None] = mapped_column(String(10))
    channel_source: Mapped[str | None] = mapped_column(String(10))
    file_path: Mapped[str | None] = mapped_column(Text)
    file_sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    page_count: Mapped[int | None] = mapped_column(Integer)
    extracted_text: Mapped[str | None] = mapped_column(Text)
    extract_phase: Mapped[str | None] = mapped_column(String(20))   # 비동기 추출: queued|regex|done|failed
    error_message: Mapped[str | None] = mapped_column(Text)         # 추출 실패/경고 사유(보드 표시)
    status: Mapped[enums.AdvisoryStatus] = mapped_column(
        _enum(enums.AdvisoryStatus), default=enums.AdvisoryStatus.UPLOADED, nullable=False
    )
    uploaded_by: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"))
    board_post_id: Mapped[str | None] = mapped_column(String(120))  # 그룹웨어 게시판 글 ID(§★★★)
    # 내부 게시판 공개 시각 — 설정되면 /board 게시판에 노출(관리자 '게시판 게시' 시 기록).
    board_published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    cves: Mapped[list["AdvisoryCve"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan"
    )
    products: Mapped[list["AdvisoryProduct"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan",
        order_by="AdvisoryProduct.id",
    )
    comments: Mapped[list["AdvisoryComment"]] = relationship(
        back_populates="advisory", cascade="all, delete-orphan",
        order_by="AdvisoryComment.id",
    )
    # 영향 자산 매칭(읽기 전용) — 게시판에서 영향 부서/자산/담당자 집계에 사용.
    matches: Mapped[list["Match"]] = relationship(
        primaryjoin="Advisory.id == Match.advisory_id", viewonly=True,
    )


class AdvisoryCve(TimestampMixin, Base):
    __tablename__ = "advisory_cve"
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisory.id"), nullable=False)
    cve_id_text: Mapped[str] = mapped_column(String(24), nullable=False)
    cve_ref_id: Mapped[int | None] = mapped_column(ForeignKey("cve.id"))  # 명세 cve_id(FK)
    lookup_status: Mapped[enums.LookupStatus] = mapped_column(
        _enum(enums.LookupStatus), default=enums.LookupStatus.NOT_FOUND, nullable=False
    )
    extraction_confidence: Mapped[float | None] = mapped_column(Numeric(3, 2))
    source_snippet: Mapped[str | None] = mapped_column(Text)
    # 소프트 삭제(§개편) — 오추출 제거는 이력을 남기고 숨긴다. 재추출 시 삭제 의사가
    # 보존되고, 실수 삭제는 '복원'으로 즉시 되살릴 수 있다.
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    advisory: Mapped[Advisory] = relationship(back_populates="cves")
    cve: Mapped[Cve | None] = relationship()

    __table_args__ = (
        UniqueConstraint("advisory_id", "cve_id_text", name="uq_advisory_cve"),
    )


class AdvisoryProduct(TimestampMixin, Base):
    """권고문 본문에서 추출/수동등록한 영향 제품·버전 규칙(§개편 — 추출 엔진).

    status:  SUGGESTED(추출 제안) | CONFIRMED(관리자 확인) | DELETED(삭제 — 복원 가능)
    origin:  EXTRACTED(본문 추출) | MANUAL(관리자 수동 추가)
    affected_versions 는 CVE 규칙과 동일 형식(열거/{lt,lte,gt,gte,eq}/{range}/"*").
    fixed_version 은 '이 버전 이상으로 업데이트' 류 조치 권고 버전(영향 아님).
    """
    __tablename__ = "advisory_product"
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisory.id"), nullable=False, index=True)
    product_name: Mapped[str] = mapped_column(String(200), nullable=False)
    product_key: Mapped[str] = mapped_column(String(80), nullable=False)
    affected_versions: Mapped[object | None] = mapped_column(JSON)
    fixed_version: Mapped[str | None] = mapped_column(String(120))
    source_snippet: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float | None] = mapped_column(Numeric(3, 2))
    status: Mapped[str] = mapped_column(String(16), default="SUGGESTED", nullable=False)
    origin: Mapped[str] = mapped_column(String(16), default="EXTRACTED", nullable=False)

    advisory: Mapped[Advisory] = relationship(back_populates="products")

    __table_args__ = (
        UniqueConstraint("advisory_id", "product_key", name="uq_advisory_product"),
    )


class AdvisoryIndex(TimestampMixin, Base):
    """권고문 관리 인덱스(§개편 후속) — 문서번호 중심의 검색·필터 전용 비정규화 테이블.

    CVE 가 없는 권고문도 문서번호로 관리·검색되도록, 권고문 1건당 1행으로
    문서번호·CVE 목록·대상 제품(복수)·버전(복수)·날짜·배포기관을 집약한다.
    원천 데이터가 바뀔 때마다 reindex_advisory() 로 재생성(멱등 upsert)된다.
    search_text 는 전 필드를 소문자로 이어붙인 검색용 열 — LIKE 한 번으로 전 필드 검색.
    """
    __tablename__ = "advisory_index"
    # ondelete=CASCADE — 파생(비정규화) 테이블이 원본 삭제를 막으면 안 된다.
    advisory_id: Mapped[int] = mapped_column(
        ForeignKey("advisory.id", ondelete="CASCADE"), nullable=False, unique=True)
    doc_no: Mapped[str | None] = mapped_column(String(120), index=True)
    source_org: Mapped[str | None] = mapped_column(String(80), index=True)
    received_at: Mapped[date | None] = mapped_column(Date)
    due_at: Mapped[date | None] = mapped_column(Date)
    cves: Mapped[list | None] = mapped_column(JSON)       # ["CVE-2026-1234", ...]
    products: Mapped[list | None] = mapped_column(JSON)   # [{"name","key","versions"}, ...]
    search_text: Mapped[str | None] = mapped_column(Text)

    advisory: Mapped["Advisory"] = relationship()


class AdvisoryComment(TimestampMixin, Base):
    """내부 게시판 댓글 — 사내 누구나(무인증) 권고문에 회신/질의.

    선택적으로 조치상태(ack_status)를 첨부하면, 해당 (권고문, 부서)의 발송 내역
    ack 로 동기화된다(둘 다 — 자유 댓글 + 공식 회신 겸용).
    """
    __tablename__ = "advisory_comment"
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisory.id"), nullable=False, index=True)
    author_name: Mapped[str] = mapped_column(String(80), nullable=False)
    # 부서: 드롭다운(검색)으로 기존 부서 선택. 직접입력 대비 이름 스냅샷도 보관.
    author_department_id: Mapped[int | None] = mapped_column(ForeignKey("department.id"))
    author_department_name: Mapped[str | None] = mapped_column(String(120))
    body: Mapped[str] = mapped_column(Text, nullable=False)
    # 선택 조치상태(첨부 시 부서 ack 동기화). 미첨부면 None = 일반 댓글.
    ack_status: Mapped[enums.AckStatus | None] = mapped_column(_enum(enums.AckStatus))
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)  # 관리자 작성 표식
    # 증빙 첨부(조치 결과 스크린샷·문서 등). 조치상태 회신 시 발송이력 ack 증빙으로 동기화.
    evidence_path: Mapped[str | None] = mapped_column(Text)
    evidence_name: Mapped[str | None] = mapped_column(String(200))

    advisory: Mapped["Advisory"] = relationship(back_populates="comments")
    department: Mapped["Department | None"] = relationship()


class MessageTemplate(TimestampMixin, Base):
    """발송 문구 프리셋 — 관리자가 자주 쓰는 안내 문구를 저장/재사용(추가·삭제).

    발송이력·조치관리 화면에서 미회신 부서 재발송 시 본문 템플릿으로 사용한다.
    본문에는 {제목}·{문서번호}·{기한}·{부서} 플레이스홀더를 쓸 수 있다(치환은 화면에서).
    """
    __tablename__ = "message_template"
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)


class Match(TimestampMixin, Base):
    __tablename__ = "match"
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisory.id"), nullable=False)
    advisory_cve_id: Mapped[int] = mapped_column(ForeignKey("advisory_cve.id"), nullable=False)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), nullable=False)
    match_reason: Mapped[dict | None] = mapped_column(JSON)
    status: Mapped[enums.MatchStatus] = mapped_column(
        _enum(enums.MatchStatus), default=enums.MatchStatus.MATCHED, nullable=False
    )
    excluded_by: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"))
    excluded_reason: Mapped[str | None] = mapped_column(String(200))
    # ── 자산별 조치 회신(게시판에서 담당자가 자산 단위로 체크·처리) ──
    ack_status: Mapped[enums.AckStatus] = mapped_column(
        _enum(enums.AckStatus), default=enums.AckStatus.NONE, nullable=False
    )
    ack_by: Mapped[str | None] = mapped_column(String(80))        # 처리한 담당자명
    ack_note: Mapped[str | None] = mapped_column(Text)            # 회신 메모(불가 사유 등)
    ack_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    advisory_cve: Mapped[AdvisoryCve] = relationship()
    asset: Mapped[Asset] = relationship()

    __table_args__ = (
        UniqueConstraint("advisory_cve_id", "asset_id", name="uq_match_cve_asset"),
    )


class Notification(TimestampMixin, Base):
    __tablename__ = "notification"
    advisory_id: Mapped[int] = mapped_column(ForeignKey("advisory.id"), nullable=False)
    department_id: Mapped[int] = mapped_column(ForeignKey("department.id"), nullable=False)
    channels: Mapped[list] = mapped_column(JSON, default=list)
    message_body: Mapped[str | None] = mapped_column(Text)
    asset_ids: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[enums.NotificationStatus] = mapped_column(
        _enum(enums.NotificationStatus), default=enums.NotificationStatus.PENDING, nullable=False
    )
    ack_status: Mapped[enums.AckStatus] = mapped_column(
        _enum(enums.AckStatus), default=enums.AckStatus.NONE, nullable=False
    )
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_by: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"))
    idempotency_key: Mapped[str | None] = mapped_column(String(80), unique=True)
    # ── 조치 회신 루프(§★★★★★) ──
    ack_note: Mapped[str | None] = mapped_column(Text)            # 회신 코멘트(불가 사유 등)
    ack_evidence_path: Mapped[str | None] = mapped_column(Text)   # 증빙 파일 경로
    ack_evidence_name: Mapped[str | None] = mapped_column(String(200))
    ack_updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ack_by: Mapped[str | None] = mapped_column(String(80))        # 회신 부서 담당자
    # ── 리마인드(§★★★★) ──
    reminded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reminder_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    advisory: Mapped[Advisory] = relationship()
    department: Mapped[Department] = relationship()


class CveFeedImport(TimestampMixin, Base):
    __tablename__ = "cve_feed_import"
    source: Mapped[str | None] = mapped_column(String(40))
    import_mode: Mapped[enums.ImportMode] = mapped_column(
        _enum(enums.ImportMode), default=enums.ImportMode.FILE_UPLOAD, nullable=False
    )
    file_name: Mapped[str | None] = mapped_column(String(200))
    file_sha256: Mapped[str | None] = mapped_column(String(64))
    file_path: Mapped[str | None] = mapped_column(Text)
    added_count: Mapped[int] = mapped_column(Integer, default=0)
    updated_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[enums.FeedImportStatus] = mapped_column(
        _enum(enums.FeedImportStatus), default=enums.FeedImportStatus.VALIDATED, nullable=False
    )
    applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)   # 적용 실패 사유(§개편 후속)
    # 검증 단계에서 산출한 파싱 결과를 적용 시점까지 임시 보관.
    staged_payload: Mapped[list | None] = mapped_column(JSON)


class ExclusionRule(TimestampMixin, Base):
    """오탐 제외 기억(§★★★) — (자산, 제품군) 조합을 다음 권고문 매칭에서 자동 제안."""
    __tablename__ = "exclusion_rule"
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), nullable=False)
    product_key: Mapped[str] = mapped_column(String(80), nullable=False)
    reason: Mapped[str | None] = mapped_column(String(200))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("app_user.id"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    asset: Mapped["Asset"] = relationship()

    __table_args__ = (
        UniqueConstraint("asset_id", "product_key", name="uq_exclusion_asset_product"),
    )


class AuditLog(TimestampMixin, Base):
    __tablename__ = "audit_log"
    actor_id: Mapped[int | None] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    entity_type: Mapped[str | None] = mapped_column(String(60))
    entity_id: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[dict | None] = mapped_column(JSON)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(400))
