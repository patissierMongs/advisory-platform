"""프로토타입 데이터 시드 — 부팅 즉시 UI가 동작하도록 동일 데이터를 적재.

상태 재현:
  · 로컬 CVE DB에 기본 4건(국정원 권고문 중 조회 가능분).
  · 한컴/Acrobat 2건은 미등록(NOT_FOUND) → CVE 피드 업로드로 해소(samples/ 피드 파일).
  · 활성 권고문은 Step2(미등록 2건)에서 시작 → 프로토타입과 동일한 진입점.
  · 발송 이력/대시보드용 과거 완료 권고문 1건.
"""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import enums
from .config import UPLOAD_DIR
from .core import extract
from .models import (
    AdvisoryCve, Advisory, AppUser, Asset, Cve, Department, Notification,
)

DEPARTMENTS = [
    "정보화담당관실", "도로국", "건축정책관실", "교통물류실",
    "국토정책관실", "주택토지실", "항공정책실", "수자원정책관실",
]

# product_raw, product_key, version_raw/version_norm 는 동일 문자열 사용.
ASSETS = [
    ("PC-0142", "정보화담당관실", "Windows 11", "windows_11", "23H2", "10.20.3.14", "김민수"),
    ("PC-0188", "도로국", "Windows 11", "windows_11", "22H2", "10.20.5.21", "이서연"),
    ("PC-0233", "건축정책관실", "Windows 11", "windows_11", "23H2", "10.20.6.33", "최유진"),
    ("PC-0260", "교통물류실", "Windows 11", "windows_11", "22H2", "10.20.7.12", "한지훈"),
    ("PC-0420", "국토정책관실", "Windows 11", "windows_11", "23H2", "10.20.9.07", "윤가람"),
    ("PC-0301", "주택토지실", "Windows 10", "windows_10", "22H2", "10.20.8.44", "정다은"),
    ("SRV-002", "정보화담당관실", "Windows Server", "windows_server", "2022", "10.20.1.05", "박정호"),
    ("SRV-009", "도로국", "Windows Server", "windows_server", "2019", "10.20.1.21", "오세훈"),
    ("OFC-110", "건축정책관실", "Microsoft Office", "microsoft_office", "2021", None, "신예린"),
    ("OFC-118", "교통물류실", "Microsoft Office", "microsoft_office", "2019", None, "강동원"),
    ("OFC-203", "주택토지실", "Microsoft Office", "microsoft_office", "2021", None, "임수정"),
    ("WEB-031", "정보화담당관실", "Google Chrome", "google_chrome", "122.x", None, "자동배포"),
    ("WEB-044", "도로국", "Google Chrome", "google_chrome", "121.x", None, "자동배포"),
    ("HWP-070", "항공정책실", "한컴오피스", "hancom_office", "2022", None, "송민재"),
    ("HWP-072", "수자원정책관실", "한컴오피스", "hancom_office", "2020", None, "배현우"),
    ("PDF-090", "건축정책관실", "Adobe Acrobat", "adobe_acrobat", "DC 2021", None, "노아름"),
]

# 기본 등록 CVE(조회 가능). 한컴/Acrobat 2건은 피드로 추가(samples/).
CVE_BASE = [
    ("CVE-2026-21345", "Microsoft Windows 11", "windows_11", ["22H2", "23H2"],
     enums.Severity.CRITICAL, 9.8, "원격 코드 실행(RCE)", "2026-06-10", "NVD"),
    ("CVE-2026-21360", "Windows Server", "windows_server", ["2019", "2022"],
     enums.Severity.CRITICAL, 9.1, "권한 상승(EoP)", "2026-06-10", "NVD"),
    ("CVE-2026-21401", "Microsoft Office", "microsoft_office", ["2019", "2021"],
     enums.Severity.HIGH, 8.1, "임의 코드 실행", "2026-06-10", "NVD"),
    ("CVE-2026-30012", "Google Chrome", "google_chrome", {"lt": "124"},
     enums.Severity.HIGH, 8.3, "메모리 손상", "2026-06-11", "NVD"),
]

ADVISORY_CVE_CODES = [
    "CVE-2026-21345", "CVE-2026-21360", "CVE-2026-21401",
    "CVE-2026-30012", "CVE-2026-44120", "CVE-2026-45088",
]

ADVISORY_TEXT = (
    "국가정보원 사이버안보 보안권고문\n"
    "문서번호 : 국정원-사이버-2026-0612\n"
    "제목 : 2026년 6월 정기 보안 업데이트 적용 권고\n"
    "적용 대상 및 조치사항\n"
    "1. 원격 코드 실행 취약점 (CVE-2026-21345), 긴급\n"
    "2. 권한 상승 취약점 (CVE-2026-21360), 긴급\n"
    "3. 임의 코드 실행 취약점 (CVE-2026-21401), 높음\n"
    "4. 메모리 손상 취약점 (CVE-2026-30012), 높음\n"
    "5. 정보 유출 취약점 (CVE-2026-44120), 중간\n"
    "6. 문서 처리 코드 실행 취약점 (CVE-2026-45088), 높음\n"
    "조치 기한 : 2026. 6. 26.(목)까지\n"
)


def _minimal_pdf(lines: list[str]) -> bytes:
    """ASCII 텍스트 1페이지 최소 PDF(유효·열람 가능). 한글은 extracted_text 로 표시."""
    def esc(s: str) -> str:
        return "".join(c for c in s if 32 <= ord(c) < 127).replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")

    content = "BT /F1 11 Tf 50 760 Td 14 TL\n" + "".join(f"({esc(ln)}) Tj T*\n" for ln in lines) + "ET"
    objs = [
        "<</Type/Catalog/Pages 2 0 R>>",
        "<</Type/Pages/Kids[3 0 R]/Count 1>>",
        "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>",
        f"<</Length {len(content)}>>\nstream\n{content}\nendstream",
        "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
    ]
    out = b"%PDF-1.4\n"
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref_pos = len(out)
    out += f"xref\n0 {len(objs)+1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += f"trailer<</Size {len(objs)+1}/Root 1 0 R>>\nstartxref\n{xref_pos}\n%%EOF".encode()
    return out


def seed(db: Session) -> None:
    if db.scalar(select(func.count(Department.id))):
        return  # 이미 시드됨

    analyst = AppUser(username="analyst", display_name="정보보호팀 · 관제", role=enums.UserRole.ANALYST)
    db.add(analyst)

    depts = {name: Department(name=name, code=f"DEPT{i:02d}",
                              messenger_id=f"room-{i:02d}", email=f"dept{i:02d}@example.go.kr")
             for i, name in enumerate(DEPARTMENTS, start=1)}
    db.add_all(depts.values())
    db.flush()

    for asset_no, dept, praw, pkey, ver, ip, owner in ASSETS:
        db.add(Asset(asset_no=asset_no, department_id=depts[dept].id, product_raw=praw,
                     product_key=pkey, version_raw=ver, version_norm=ver, ip=ip, owner_name=owner,
                     status=enums.AssetStatus.NORMAL))

    for cid, pname, pkey, versions, sev, cvss, desc, pub, src in CVE_BASE:
        db.add(Cve(cve_id=cid, product_name=pname, product_key=pkey, affected_versions=versions,
                   severity=sev, cvss_score=cvss, description=desc,
                   published_at=date.fromisoformat(pub), source=src))
    db.flush()

    # 활성 권고문(Step2 진입점). PDF 저장 + advisory_cve 적재(4 FOUND / 2 NOT_FOUND).
    pdf_bytes = _minimal_pdf(["National Cyber Security Advisory", "Doc: 국정원-사이버-2026-0612"]
                             + [c for c in ADVISORY_CVE_CODES])
    sha = extract.sha256_bytes(pdf_bytes)
    pdf_path = UPLOAD_DIR / f"{sha}.pdf"
    pdf_path.write_bytes(pdf_bytes)

    adv = Advisory(
        doc_no="국정원-사이버-2026-0612",
        title="2026년 6월 MS 정기 보안 업데이트 및 주요 SW 취약점 조치 권고",
        source_org="국가정보원", receive_channel=enums.ReceiveChannel.NCST,
        received_at=date(2026, 6, 12), due_at=date(2026, 6, 26),
        file_path=str(pdf_path), file_sha256=sha, page_count=1,
        extracted_text=ADVISORY_TEXT, status=enums.AdvisoryStatus.NEEDS_CVE_UPDATE,
        uploaded_by=analyst.id,
    )
    db.add(adv)
    db.flush()
    for code in ADVISORY_CVE_CODES:
        cve = db.scalar(select(Cve).where(Cve.cve_id == code))
        db.add(AdvisoryCve(
            advisory_id=adv.id, cve_id_text=code, cve_ref_id=cve.id if cve else None,
            lookup_status=enums.LookupStatus.FOUND if cve else enums.LookupStatus.NOT_FOUND,
            extraction_confidence=1.0, source_snippet=f"... {code} ...",
        ))

    # 과거 완료 권고문 + 발송 이력(대시보드/이력 화면용).
    past = Advisory(
        doc_no="국토부-정보보호-2026-0521",
        title="리눅스 커널 권한상승 취약점 긴급 패치 권고",
        source_org="국토교통부", receive_channel=enums.ReceiveChannel.OFFICIAL_DOC,
        received_at=date(2026, 5, 28), due_at=date(2026, 6, 5),
        page_count=1, extracted_text="CVE-2026-10010 linux kernel",
        status=enums.AdvisoryStatus.COMPLETED, uploaded_by=analyst.id,
    )
    ppdf = _minimal_pdf(["Linux Kernel EoP Advisory", "Doc: 국토부-정보보호-2026-0521"])
    psha = extract.sha256_bytes(ppdf)
    (UPLOAD_DIR / f"{psha}.pdf").write_bytes(ppdf)
    past.file_path = str(UPLOAD_DIR / f"{psha}.pdf")
    past.file_sha256 = psha
    db.add(past)
    db.flush()

    base_dt = datetime(2026, 6, 5, 14, 22, tzinfo=timezone.utc)
    for i, (dept, acked, channels) in enumerate([
        ("정보화담당관실", enums.AckStatus.DONE, ["MESSENGER", "MAIL"]),
        ("도로국", enums.AckStatus.DONE, ["MESSENGER", "MAIL"]),
        ("건축정책관실", enums.AckStatus.IN_PROGRESS, ["MAIL"]),
        ("교통물류실", enums.AckStatus.DONE, ["MESSENGER"]),
        ("주택토지실", enums.AckStatus.NONE, ["MAIL"]),
    ]):
        db.add(Notification(
            advisory_id=past.id, department_id=depts[dept].id, channels=channels,
            message_body=f"[보안조치 요청] {past.title}", asset_ids=[],
            status=enums.NotificationStatus.ACKED if acked == enums.AckStatus.DONE else enums.NotificationStatus.SENT,
            ack_status=acked, sent_at=base_dt - timedelta(days=i // 3),
            sent_by=analyst.id, idempotency_key=f"seed-past-{i}",
        ))

    db.commit()
