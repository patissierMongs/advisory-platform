"""요청 본문 스키마(Pydantic). 응답은 대부분 dict 로 직렬화한다."""
from __future__ import annotations

from pydantic import BaseModel, Field

from .enums import AckStatus, MatchStatus, NotifyChannel, UserRole


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=1, max_length=200)


class UserCreateIn(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    display_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=200)
    role: UserRole = UserRole.ADMIN


class UserPatchIn(BaseModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=120)
    role: UserRole | None = None
    is_active: bool | None = None


class PasswordResetIn(BaseModel):
    new_password: str = Field(min_length=1, max_length=200)


class MatchPatch(BaseModel):
    status: MatchStatus
    reason: str | None = None


class AckPatch(BaseModel):
    ack_status: AckStatus
    note: str | None = None       # 회신 코멘트 / 조치불가 사유
    by: str | None = None         # 회신 담당자


class CveAddRequest(BaseModel):
    cve_id: str                   # 수동 추가할 CVE 코드


class CvePatchRequest(BaseModel):
    """추출 CVE 코드 수정(§개편) — 오추출을 그 자리에서 교정."""
    cve_id: str


class AdvisoryProductIn(BaseModel):
    """영향 제품 수동 추가(§개편)."""
    product_name: str = Field(min_length=1, max_length=200)
    # 규칙 형식: ["2019","2021"] | {"lt"/"lte"/"gt"/"gte"/"eq":..} | {"range":[a,b]} | "*"
    affected_versions: object | None = None
    fixed_version: str | None = None


class AdvisoryProductPatch(BaseModel):
    """영향 제품 수정(§개편) — 전달 필드만 갱신."""
    product_name: str | None = None
    affected_versions: object | None = None
    fixed_version: str | None = None
    status: str | None = None              # SUGGESTED | CONFIRMED


class ProductApplyRequest(BaseModel):
    """추출 제품 → CVE 적용(§개편)."""
    cve_id: str


class BulkSourceRequest(BaseModel):
    """출처기관 일괄 지정(§개편)."""
    ids: list[int] = Field(min_length=1)
    source_org: str = Field(min_length=1, max_length=80)
    only_empty: bool = True                # 빈 출처만 갱신(기본) — 기존 값 보호


class AdvisoryMetaPatch(BaseModel):
    """관리자 수동 지정(§8·9) — 본문에서 추출되지 않은 조치기한·접수경로를 직접 입력.

    전달한 필드만 갱신(부분 수정). 빈 값/None 으로 보내면 해당 항목을 '미지정'으로 비운다.
    """
    due_at: str | None = None              # 'YYYY-MM-DD'
    receive_channel: str | None = None     # NCST | WEBMAIL | OFFICIAL_DOC
    source_org: str | None = None          # 출처기관(§개편 — 개별 수정)


class GroupwareAckWebhook(BaseModel):
    department: str
    status: str                   # DONE | IN_PROGRESS | UNABLE (또는 한글)
    note: str | None = None
    by: str | None = None
    # 대상 권고문 식별 — 미지정 시 해당 부서의 미종료 발송이 1건일 때만 처리(오귀속 방지).
    advisory_id: int | None = None
    doc_no: str | None = None


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
    all_sheets: bool = False      # 모든 시트를 같은 매핑으로 일괄 적재(§개편 — 다중 시트)


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
    """내부 게시판 댓글(무인증) — 부서는 드롭다운 선택(id) 또는 직접입력(name).

    match_ids: 영향 자산 표에서 체크한 자산(선택). ack_status·부서와 함께 주어지면 해당
    자산의 조치상태도 댓글로 함께 갱신한다(이름은 무관, 부서명만 일치하면 됨).
    """
    author_name: str = Field(min_length=1, max_length=80)
    department_id: int | None = None
    department_name: str | None = None        # 직접입력 시 부서명(id 미지정)
    body: str = Field(min_length=1)
    ack_status: AckStatus | None = None       # 선택: 조치상태 첨부 → 부서 ack 동기화
    match_ids: list[int] | None = None        # 선택: 체크한 자산 → 자산별 ack 동기화
    # is_admin 은 공개 입력에서 받지 않는다(관리자 배지 스푸핑 차단 — 서버가 항상 False 로 저장).


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
