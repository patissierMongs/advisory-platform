# 진행 기록

**한국어** | [English](PROGRESS.en.md)

## 최종 목표

국가정보원·상급기관 등에서 받은 보안권고문 PDF(Portable Document Format)를 올리면 CVE(Common Vulnerabilities and Exposures) 추출 → 로컬 CVE DB(Database) 조회 → 자산 매칭 → 부서 발송 → 조치 회신 추적까지 한 시스템에서 처리하는 것이 목표입니다. 인터넷이 없는 폐쇄망에서 설치·실행·운영할 수 있어야 하며, 관제 담당자 한 명이 반복 작업 없이 권고문을 처리할 수 있어야 합니다.

## 현재 구현 상태

2026-09-27에 코드를 직접 읽고, `pytest tests`(334건 통과)와 `smoke_test.py`(74건 통과)를 실행하고, `ADVISORY_SEED=true` 로 서버를 띄워 브라우저로 STEP 2~4 흐름을 확인한 결과입니다.

| 기능 | 상태 | 근거 코드 |
|---|---|---|
| PDF 업로드·CVE 정규식 추출(띄어쓰기·구분자 변형 정규화) | 구현됨 | `app/core/extract.py`, `app/routers/advisories.py` |
| 표 우선 제품·영향 버전·해결 버전 추출(좌표 기반 표 복원) | 구현됨 | `app/core/pdf_tables.py`, `app/core/product_extract.py` |
| CVE·제품 수동 추가·수정·재추출 | 구현됨 | `app/routers/advisories.py` (`POST /advisories/{id}/cves` 등) |
| 원문 PDF 열람과 CVE 위치 강조 | 구현됨 | `app/core/pdf_render.py`, `app/routers/advisories.py` (`/pdf-view`) |
| CVE 피드 반입(NVD(National Vulnerability Database) 1.1·2.0 JSON(JavaScript Object Notation), CSV(Comma-Separated Values), KrCERT(Korea Computer Emergency Response Team) JSON, gzip)·검증 후 적용 | 구현됨 | `app/core/feeds.py`, `app/routers/cve_feeds.py` |
| 피드 적용 후 미완료 권고문 재처리 | 구현됨 | `app/core/advisory_ops.py` |
| 미등록 CVE가 있으면 매칭 차단(서버 게이트, 409) | 구현됨 | `app/routers/matches.py` |
| 자산관리대장 엑셀 가져오기(미리보기·열 매핑·다중 시트·사용자 필드) | 구현됨 | `app/core/assets_import.py`, `app/routers/assets.py` |
| 제품 정규화·버전 비교·자산 매칭 | 구현됨 | `app/core/normalize.py`, `app/core/versioning.py`, `app/core/matching.py` |
| 오탐 제외와 다음 권고문에서 제외 후보 표시 | 구현됨 | `app/core/exclusions.py`, `app/routers/remediation.py` (`/exclusion-rules`) |
| 부서별 메시지 생성·SMTP(Simple Mail Transfer Protocol) 메일·메신저/그룹웨어 범용 웹훅·멱등성 | 구현됨 | `app/core/notify.py`, `app/core/groupware.py`, `app/routers/notifications.py` |
| 조치 회신(완료·진행중·불가)·증빙 업로드 | 구현됨 | `app/core/remediation.py`, `app/routers/notifications.py` |
| 엑셀·HTML(HyperText Markup Language) 보고서 | 구현됨 | `app/core/reports.py`, `app/routers/remediation.py` |
| 기한 임박 리마인드 | 부분 구현 | `app/core/remediation.py` (`due_reminders`), `POST /advisories/{id}/remind` — 대상 목록과 수동 발송만 있고 자동 예약 발송은 없음 |
| 내부 게시판(무인증 열람·댓글·자산별 조치 회신·증빙) | 구현됨 | `app/routers/board.py`, `web/public/board.html` |
| 발송이력·조치관리 콘솔(권고문별·부서별, 미회신 재발송) | 구현됨 | `app/routers/history.py`, `web/admin/history.html` |
| 대시보드 | 구현됨 | `app/routers/dashboard.py` |
| 관리자 로그인·최초 비밀번호 변경·CSRF(Cross-Site Request Forgery)·로그인 잠금 | 구현됨 | `app/auth.py`, `app/routers/auth.py`, `web/public/login.html` |
| 그룹웨어 회신 웹훅 HMAC(Hash-based Message Authentication Code) 서명 검증 | 구현됨 | `app/routers/webhooks.py` |
| 감사 로그(활동 기록) | 구현됨 | `app/audit.py`, `app/routers/audit.py` |
| `data` 폴더 NTFS(New Technology File System) ACL(Access Control List) 적용 | 구현됨(Windows 전용, 이 환경에서는 단위 테스트로만 확인) | `app/core/winacl.py`, `scripts/harden_data_acl.bat` |
| 오프라인 휠 설치 실행 스크립트 | 구현됨 | `start.sh`, `start.bat`, `scripts/prepare_offline.*` |
| Windows 올인원 번들(Python 3.12·3.13, 오프라인 빌드, zip·7z 분할) | 구현됨(이 환경에서 빌드는 실행하지 않음) | `build_allinone.py`, `scripts/collect_offline_bundle.py` |
| NVD 동기화 PowerShell 도구 | 구현됨(앱과 별개 도구, 결과 파일은 화면에서 업로드) | `nvd_powershell_sync/` |
| 앱 안의 CVE 피드 자동 동기화 | 미구현 | 화면에 "매일 06:00 (NVD)" 문구만 있음(`web/admin/app.dc.html`), 서버에 스케줄러 없음 |
| 스캔본(이미지) PDF OCR(Optical Character Recognition) | 미구현 | `app/core/extract.py` 주석에 범위 밖으로 명시 |
| 디자인 시스템 번들 재생성 | 부분 구현 | `ds-bundle/` 결과물은 있으나 `.ds-build/build.mjs` 가 이동 전 경로(`web/vendor/`, `web/app.dc.html`)를 읽음 |
| 브라우저 E2E(End-to-End) 테스트·CI(Continuous Integration) | 미구현 | `docs/testing-guide.md` 에 계획만 있음, `tests/` 에 브라우저 테스트 없음 |

## 작업 이력

`git log` 의 커밋 날짜를 KST(Korea Standard Time, Asia/Seoul)로 바꿔 정리했습니다. 커밋 시각은 +0900과 +0000이 섞여 저장되어 있어 모두 KST로 환산했습니다.

| 날짜(KST) | 주요 작업 |
|---|---|
| 2026-06-18 | 초기 커밋(FastAPI 백엔드 + 프론트엔드 연동), CVE 피드 일괄 upsert·gzip 지원, LLM(Large Language Model) 추출 계층 제거 후 정규식 단독 추출 |
| 2026-06-19 | 내부 게시판 추가(부서 필터·검색·원문 PDF·증빙), 발송이력 목업 3종과 마스터-디테일 콘솔(`/admin/history`), NVD 동기화 도구, `start.bat` 오류 수정, 포트스캔 도구 실험 |
| 2026-06-20 ~ 06-21 | 포트스캔 기능 실험 후 전체 롤백(별도 프로젝트로 분리), 발송이력 개편, 조치기한·접수경로 추출, 코드 리뷰 반영, 운영 준비 |
| 2026-06-22 ~ 06-24 | 보안 검증 보고서, 실행 경로의 인터넷 의존 제거, 올인원 번들 강화, 자산 가져오기 열 매핑 자유화, NVD 동기화 안정화 |
| 2026-07-02 ~ 07-07 | QA(Quality Assurance) 테스트 가이드, 브랜치 통합 중 유실된 기능 복원, 실사용 시나리오 27건 점검과 결함 수정 |
| 2026-07-20 ~ 07-25 | 추출 엔진·현장 보정·자산 단위 조치율 대규모 개편, NVD 1.1 연도별 덤프 지원, 피드→추출 사전 동기화, 저장형 XSS(Cross-Site Scripting) 등 보안 검토 후속 수정, 버전 매칭 오답 수정 |
| 2026-08-06 | 관리자 인증(비밀번호 해시·세션·CSRF·잠금), 웹훅 HMAC, 관리자 API(Application Programming Interface) 전면 게이트, 증빙 업로드 강화, NTFS ACL, 로그인 화면, 표 기반 제품·버전 추출, 올인원 번들 Python 3.12/3.13·오프라인 빌드·분할 옵션 |
| 2026-09-27 | 문서 정리: 기존 README를 `docs/상세_운영_가이드.md` 로 옮기고, 한국어·영어 README와 스크린샷, 이 진행 기록 추가 |
