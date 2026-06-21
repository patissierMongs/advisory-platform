"""요청 본문 스키마(Pydantic). 응답은 대부분 dict 로 직렬화한다."""
from __future__ import annotations

from pydantic import BaseModel, Field

from .enums import AckStatus, MatchStatus, NotifyChannel


class MatchPatch(BaseModel):
    status: MatchStatus
    reason: str | None = None


class AckPatch(BaseModel):
    ack_status: AckStatus
    note: str | None = None       # 회신 코멘트 / 조치불가 사유
    by: str | None = None         # 회신 담당자


class CveAddRequest(BaseModel):
    cve_id: str                   # 수동 추가할 CVE 코드


class GroupwareAckWebhook(BaseModel):
    department: str
    status: str                   # DONE | IN_PROGRESS | UNABLE (또는 한글)
    note: str | None = None
    by: str | None = None


class NotifyDept(BaseModel):
    department_id: int
    channels: list[NotifyChannel] = Field(default_factory=lambda: [NotifyChannel.MAIL, NotifyChannel.WEB_UI])


class NotifyRequest(BaseModel):
    departments: list[NotifyDept] | None = None
    all: bool = False
    channels: list[NotifyChannel] | None = None  # all=true 일 때 공통 채널


class NotifyTestRequest(BaseModel):
    to: str = Field(min_length=3, max_length=200)


class AssetCommitRequest(BaseModel):
    # 값은 컬럼 레터("F") 또는 분할 스펙 {"col":"F","sep":",","part":1}
    mapping: dict[str, str | dict]
    sheet: str | None = None
    header_row: int | None = None  # 1-기반. 미지정 시 자동 감지
    header_rows: int = 1           # 다단 헤더 줄 수(예: 2층 헤더는 2)
    mode: str = "append"          # append | replace
    on_warning: str = "skip"      # skip | reject
    create_departments: bool = True  # 자산대장의 미등록 부서 자동 생성(자산대장=부서 원천)


class DepartmentIn(BaseModel):
    name: str
    code: str | None = None
    messenger_id: str | None = None
    email: str | None = None
    is_active: bool = True


class MappingPresetIn(BaseModel):
    name: str
    mapping: dict[str, str | dict]


class MessageTemplateIn(BaseModel):
    """발송 문구 프리셋 등록 — 제목 + 본문."""
    title: str = Field(min_length=1, max_length=120)
    body: str = Field(min_length=1)


class CommentIn(BaseModel):
    """내부 게시판 댓글(무인증) — 부서는 드롭다운 선택(id) 또는 직접입력(name)."""
    author_name: str = Field(min_length=1, max_length=80)
    department_id: int | None = None
    department_name: str | None = None        # 직접입력 시 부서명(id 미지정)
    body: str = Field(min_length=1)
    ack_status: AckStatus | None = None       # 선택: 조치상태 첨부 → 부서 ack 동기화
    is_admin: bool = False


class AssetAckIn(BaseModel):
    """게시판 자산별 조치 회신(무인증) — 담당자가 본인 자산을 체크해 개별/일괄 처리.

    부서는 드롭다운 선택(id) 권장. match_ids 의 자산이 선택 부서와 다르면 서버가 409 로 거부
    (다른 부서 자산 오처리 방지). note 는 선택(조치불가 사유 등).
    """
    author_name: str = Field(min_length=1, max_length=80)
    department_id: int | None = None
    department_name: str | None = None
    ack_status: AckStatus
    match_ids: list[int] = Field(min_length=1)
    note: str | None = None
