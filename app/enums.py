"""열거값 — 명세서 §8 부록과 1:1 대응."""
from __future__ import annotations

import enum


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"  # 긴급
    HIGH = "HIGH"          # 높음
    MEDIUM = "MEDIUM"      # 중간
    LOW = "LOW"            # 낮음


class AdvisoryStatus(str, enum.Enum):
    UPLOADED = "UPLOADED"
    EXTRACTING = "EXTRACTING"
    EXTRACTED = "EXTRACTED"
    NEEDS_CVE_UPDATE = "NEEDS_CVE_UPDATE"
    MATCHED = "MATCHED"
    NOTIFYING = "NOTIFYING"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"


class ReceiveChannel(str, enum.Enum):
    NCST = "NCST"
    WEBMAIL = "WEBMAIL"
    OFFICIAL_DOC = "OFFICIAL_DOC"


class LookupStatus(str, enum.Enum):
    FOUND = "FOUND"
    NOT_FOUND = "NOT_FOUND"


class MatchStatus(str, enum.Enum):
    MATCHED = "MATCHED"
    EXCLUDED = "EXCLUDED"


class NotificationStatus(str, enum.Enum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    ACKED = "ACKED"


class AckStatus(str, enum.Enum):
    NONE = "NONE"             # 미회신
    IN_PROGRESS = "IN_PROGRESS"  # 진행중
    DONE = "DONE"            # 조치완료
    UNABLE = "UNABLE"        # 조치불가(사유 필요)


class SlaStatus(str, enum.Enum):
    NORMAL = "NORMAL"        # 여유
    IMMINENT = "IMMINENT"    # 임박(D-3 ~ D-0)
    OVERDUE = "OVERDUE"      # 기한 초과
    DONE = "DONE"            # 조치 완료(기한 무관)


class NotifyChannel(str, enum.Enum):
    MESSENGER = "MESSENGER"
    MAIL = "MAIL"
    WEB_UI = "WEB_UI"


class AssetStatus(str, enum.Enum):
    NORMAL = "NORMAL"
    RETIRING = "RETIRING"
    RETIRED = "RETIRED"


class FeedImportStatus(str, enum.Enum):
    VALIDATED = "VALIDATED"
    APPLIED = "APPLIED"
    FAILED = "FAILED"


class AssetImportStatus(str, enum.Enum):
    PREVIEW = "PREVIEW"
    COMMITTED = "COMMITTED"
    FAILED = "FAILED"


class ImportMode(str, enum.Enum):
    FILE_UPLOAD = "FILE_UPLOAD"
    SCHEDULED_SYNC = "SCHEDULED_SYNC"


class UserRole(str, enum.Enum):
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"
    SYSTEM = "SYSTEM"


# 외부 피드 → 내부 severity 매핑 (§4.4)
def severity_from_cvss(score: float | None) -> Severity:
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


ACK_KO = {
    AckStatus.NONE: "미회신",
    AckStatus.IN_PROGRESS: "진행중",
    AckStatus.DONE: "조치완료",
    AckStatus.UNABLE: "조치불가",
}


def sla_status(due_at, all_done: bool, today=None) -> SlaStatus:
    """기한·완료 여부 → SLA 상태. (D-day 트래킹 §★★★★)"""
    if all_done:
        return SlaStatus.DONE
    if due_at is None:
        return SlaStatus.NORMAL
    import datetime as _dt

    today = today or _dt.date.today()
    days = (due_at - today).days
    if days < 0:
        return SlaStatus.OVERDUE
    if days <= 3:
        return SlaStatus.IMMINENT
    return SlaStatus.NORMAL


# 한글 표기(피드 CSV·UI 라벨 상호변환용)
SEVERITY_KO = {
    Severity.CRITICAL: "긴급",
    Severity.HIGH: "높음",
    Severity.MEDIUM: "중간",
    Severity.LOW: "낮음",
}
KO_TO_SEVERITY = {v: k for k, v in SEVERITY_KO.items()}
