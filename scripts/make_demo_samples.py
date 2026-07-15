#!/usr/bin/env python3
"""데모 샘플 생성기 — samples/demo_advisories/ 를 통째로 재생성한다.

폴더째 업로드·출처 자동 탐지·CVE 게이트 데모를 폐쇄망에서 바로 돌릴 수 있게,
권고문 PDF(폴더 구조 포함)와 그 안의 CVE 코드를 전부 커버하는 내부 형식
CVE 피드(cve_feed_demo.json)를 한 묶음으로 만든다.

  python scripts/make_demo_samples.py            # samples/demo_advisories/ 생성
  python scripts/make_demo_samples.py --zip PATH # + 전체를 zip 으로 묶기

데모 시나리오(출처 탐지 우선순위 — 상위 폴더명 → 폴더명 → 파일명 → 본문):
  국가정보원/2026-07/…          → 상위 폴더명에서 '국가정보원' 탐지
  KISA/…                        → 폴더명에서 'KISA' 탐지
  NCSC/웹브라우저/…             → 상위 폴더명에서 'NCSC' 탐지
  FSEC-2026-0021 ….pdf          → 파일명 별칭(FSEC)에서 '금융보안원' 탐지
  기타접수/advisory-unknown-001 → 본문 'KrCERT' 에서 'KISA' 탐지
  기타접수/advisory-unknown-002 → 아무 데도 없음 → '-' 자동 지정
PDF 본문에는 카탈로그 제품(Windows·Office·HWP·V3·Chrome…)과 버전 표기(22H2,
점버전, 연도판)를 심어 게이트 자동 추출·색상 하이라이트까지 시연된다.
"""
from __future__ import annotations

import argparse
import json
import shutil
import zipfile
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
OUT = BASE / "samples" / "demo_advisories"


def _minimal_pdf(lines: list[str]) -> bytes:
    """ASCII 텍스트 1페이지 최소 PDF — app/seed.py 의 헬퍼와 동일 기법(자립 복사본)."""
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


# (상대경로, 본문 라인들) — 본문은 ASCII 만 렌더 가능(최소 PDF 폰트 제약).
ADVISORIES: list[tuple[str, list[str]]] = [
    ("국가정보원/2026-07/NIS-2026-0701 MS 정기 보안업데이트 권고.pdf", [
        "National Cyber Security Advisory  2026.7.6",
        "Doc: NIS-2026-0701   Monthly MS Security Update",
        "",
        "Affected: Microsoft Windows 11 22H2, 23H2 / Windows Server 2022",
        "          Microsoft Office 2021 (Excel, Outlook)",
        "",
        "1. CVE-2026-53770  Windows Kernel Elevation of Privilege",
        "2. CVE-2026-53771  Windows SMB Remote Code Execution",
        "3. CVE-2026-53718  Office Excel Memory Corruption",
        "",
        "Apply the July cumulative update immediately.",
    ]),
    ("국가정보원/2026-07/NIS-2026-0702 Windows 커널 취약점 긴급.pdf", [
        "URGENT Security Advisory  2026.7.9",
        "Doc: NIS-2026-0702",
        "",
        "Affected: Microsoft Windows 10 22H2 / Windows 11 23H2",
        "",
        "CVE-2026-53800  Win32k Elevation of Privilege (exploited in the wild)",
        "",
        "Workaround: disable legacy input service until patched.",
    ]),
    ("KISA/KISA-2026-0912 한컴오피스 취약점 조치 권고.pdf", [
        "KrCERT/CC Security Notice  2026.7.3",
        "Doc: KISA-2026-0912   HWP Office Suite",
        "",
        "Affected: HWP 2022, HWP 2024 (Hancom Office)",
        "",
        "1. CVE-2026-61001  HWP postscript filter code execution",
        "2. CVE-2026-61002  HWP OLE object parsing overflow",
        "",
        "Update to the latest Hancom security patch.",
    ]),
    ("KISA/KISA-2026-0913 V3 백신 업데이트 권고.pdf", [
        "KrCERT/CC Security Notice  2026.7.4",
        "Doc: KISA-2026-0913   AhnLab V3",
        "",
        "Affected: AhnLab V3 Lite 4.0, V3 365 Clinic",
        "",
        "CVE-2026-61010  V3 engine local privilege escalation",
        "",
        "Update engine to 2026.07.04.00 or later.",
    ]),
    ("NCSC/웹브라우저/NCSC-2026-0715 Chrome Edge 긴급 패치.pdf", [
        "Browser Emergency Patch Advisory  2026.7.8",
        "Doc: NCSC-2026-0715",
        "",
        "Affected: Google Chrome 126.0.6478.126 and earlier",
        "          Microsoft Edge 126.0.2592.87 and earlier",
        "",
        "1. CVE-2026-62001  Chrome V8 type confusion (0-day)",
        "2. CVE-2026-62002  Edge sandbox escape",
        "",
        "Force-update browsers across all departments.",
    ]),
    ("FSEC-2026-0021 금융권 Java 취약점 권고.pdf", [
        "Financial Sector Security Advisory  2026.7.7",
        "Doc: FSEC-2026-0021",
        "",
        "Affected: Java SE 17.0.11 and earlier (JRE, JDK)",
        "",
        "CVE-2026-63001  JNDI remote class loading vulnerability",
        "",
        "Upgrade to Java SE 17.0.12 / apply vendor mitigation.",
    ]),
    ("기타접수/advisory-unknown-001.pdf", [
        "Forwarded advisory (source in body only)  2026.7.5",
        "Issued by KrCERT vulnerability analysis team.",
        "",
        "Affected: Adobe Acrobat DC 2022",
        "",
        "CVE-2026-64001  Acrobat PDF font parsing use-after-free",
    ]),
    ("기타접수/advisory-unknown-002.pdf", [
        "Anonymous vendor bulletin  2026.7.5",
        "(no issuing organization stated anywhere)",
        "",
        "Affected: OpenSSL 3.0.13 and earlier",
        "",
        "CVE-2026-64002  TLS handshake buffer over-read",
    ]),
]

# 위 PDF 들의 CVE 를 전부 커버하는 내부 형식 피드 — 반입·적용하면 게이트가 해제된다.
FEED = {
    "source": "DEMO-BUNDLE",
    "cves": [
        {"cve_id": "CVE-2026-53770", "product_name": "Microsoft Windows 11", "product_key": "windows_11",
         "affected_versions": ["22H2", "23H2"], "severity": "높음", "cvss_score": 7.8,
         "description": "Windows 커널 권한 상승", "published_at": "2026-07-06", "source": "국가정보원"},
        {"cve_id": "CVE-2026-53771", "product_name": "Microsoft Windows Server", "product_key": "windows_server",
         "affected_versions": ["2022"], "severity": "긴급", "cvss_score": 9.8,
         "description": "SMB 원격 코드 실행", "published_at": "2026-07-06", "source": "국가정보원"},
        {"cve_id": "CVE-2026-53718", "product_name": "Microsoft Office", "product_key": "microsoft_office",
         "affected_versions": ["2021"], "severity": "높음", "cvss_score": 7.8,
         "description": "Excel 메모리 손상", "published_at": "2026-07-06", "source": "국가정보원"},
        {"cve_id": "CVE-2026-53800", "product_name": "Microsoft Windows 10", "product_key": "windows_10",
         "affected_versions": ["22H2"], "severity": "긴급", "cvss_score": 9.0,
         "description": "Win32k 권한 상승(실공격 확인)", "published_at": "2026-07-09", "source": "국가정보원"},
        {"cve_id": "CVE-2026-61001", "product_name": "한컴오피스", "product_key": "hancom_office",
         "affected_versions": ["2022", "2024"], "severity": "높음", "cvss_score": 8.1,
         "description": "HWP 포스트스크립트 필터 코드 실행", "published_at": "2026-07-03", "source": "KISA"},
        {"cve_id": "CVE-2026-61002", "product_name": "한컴오피스", "product_key": "hancom_office",
         "affected_versions": ["2022", "2024"], "severity": "중간", "cvss_score": 6.5,
         "description": "HWP OLE 개체 파싱 오버플로", "published_at": "2026-07-03", "source": "KISA"},
        {"cve_id": "CVE-2026-61010", "product_name": "AhnLab V3", "product_key": "ahnlab_v3",
         "affected_versions": ["4.0"], "severity": "중간", "cvss_score": 6.7,
         "description": "V3 엔진 로컬 권한 상승", "published_at": "2026-07-04", "source": "KISA"},
        {"cve_id": "CVE-2026-62001", "product_name": "Google Chrome", "product_key": "google_chrome",
         "affected_versions": {"lte": "126.0.6478.126"}, "severity": "긴급", "cvss_score": 9.6,
         "description": "V8 타입 혼동(0-day)", "published_at": "2026-07-08", "source": "NCSC"},
        {"cve_id": "CVE-2026-62002", "product_name": "Microsoft Edge", "product_key": "edge",
         "affected_versions": {"lte": "126.0.2592.87"}, "severity": "높음", "cvss_score": 8.8,
         "description": "샌드박스 이탈", "published_at": "2026-07-08", "source": "NCSC"},
        {"cve_id": "CVE-2026-63001", "product_name": "Java SE", "product_key": "java_se",
         "affected_versions": {"lte": "17.0.11"}, "severity": "높음", "cvss_score": 8.1,
         "description": "JNDI 원격 클래스 로딩", "published_at": "2026-07-07", "source": "금융보안원"},
        {"cve_id": "CVE-2026-64001", "product_name": "Adobe Acrobat", "product_key": "adobe_acrobat",
         "affected_versions": ["DC 2022"], "severity": "높음", "cvss_score": 7.8,
         "description": "PDF 폰트 파싱 UAF", "published_at": "2026-07-05", "source": "KISA"},
        {"cve_id": "CVE-2026-64002", "product_name": "OpenSSL", "product_key": "openssl",
         "affected_versions": {"lte": "3.0.13"}, "severity": "중간", "cvss_score": 5.9,
         "description": "TLS 핸드셰이크 버퍼 오버리드", "published_at": "2026-07-05", "source": "-"},
    ],
}


def build() -> Path:
    if OUT.exists():
        shutil.rmtree(OUT)
    for rel, lines in ADVISORIES:
        path = OUT / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(_minimal_pdf(lines))
    (OUT / "cve_feed_demo.json").write_text(
        json.dumps(FEED, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    readme = OUT / "READ ME — 데모 사용법.txt"
    readme.write_text(
        "보안권고문 데모 샘플 (올인원)\n"
        "================================\n\n"
        "1) 관리자 화면(/admin) → 권고문 처리 → 이 폴더(demo_advisories)를 통째로\n"
        "   업로드 존에 드래그&드롭하거나 '📁 폴더 업로드'로 선택하세요.\n"
        "   - 국가정보원/2026-07/…      → 상위 폴더명에서 출처 자동 탐지\n"
        "   - KISA/…                    → 폴더명에서 탐지\n"
        "   - NCSC/웹브라우저/…         → 상위 폴더명에서 탐지\n"
        "   - FSEC-2026-0021 ….pdf      → 파일명 별칭(FSEC→금융보안원)에서 탐지\n"
        "   - 기타접수/…-001.pdf        → 본문(KrCERT→KISA)에서 탐지\n"
        "   - 기타접수/…-002.pdf        → 미탐지 → '-' 자동 지정(수동 입력 데모)\n"
        "   업로드 직후 '출처 지정' 패널에서 후보 클릭 선택(복수 가능)·일괄/개별 적용을 시험하세요.\n\n"
        "2) 각 권고문 '처리 →' STEP2 에서 DB 미등록 CVE 의 직접 등록 폼과\n"
        "   PDF 색상 하이라이트(제품·버전·날짜 — 폼 필드 색과 동일)를 확인하세요.\n\n"
        "3) 일괄 해제하려면 cve_feed_demo.json 을 CVE 데이터베이스 탭에서 반입·적용하세요.\n"
        "   이 파일은 위 PDF 들의 CVE 코드 전체를 커버합니다.\n",
        encoding="utf-8")
    return OUT


def make_zip(zip_path: Path) -> Path:
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(OUT.rglob("*")):
            if p.is_file():
                z.write(p, Path("demo_advisories") / p.relative_to(OUT))
    return zip_path


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--zip", metavar="PATH", help="생성 후 전체를 zip 으로 묶을 경로")
    args = ap.parse_args()
    out = build()
    n = sum(1 for _ in out.rglob("*.pdf"))
    print(f"[demo-samples] {out} — PDF {n}건 + cve_feed_demo.json")
    if args.zip:
        zp = make_zip(Path(args.zip))
        print(f"[demo-samples] zip: {zp} ({zp.stat().st_size:,} bytes)")
