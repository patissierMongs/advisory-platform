# 보안권고문 처리 시스템

기관에 접수된 보안권고문 PDF(Portable Document Format)에서 CVE(Common Vulnerabilities and Exposures)를 뽑아 로컬 취약점 DB(Database)와 대조하고, 영향받는 자산을 찾아 담당 부서에 조치를 요청하는 폐쇄망용 웹 애플리케이션입니다.

**한국어** | [English](README.en.md)

![핵심 흐름: 권고문 목록 → CVE 조회 → 피드 반입 → 자산 매칭 → 발송 검토](docs/images/core-flow.gif)

> 화면은 모두 `ADVISORY_SEED=true` 로 넣은 데모 데이터(가상의 부서·담당자·10.20.x.x 주소)로 실제 실행해 캡처했습니다.

| 권고문 목록 | STEP 2 · CVE 추출·조회 |
|---|---|
| ![권고문 목록](docs/images/advisory-list.png) | ![CVE 조회 결과와 DB 미등록 경고](docs/images/step2-cve-lookup.png) |
| **STEP 3 · 자산 매칭** | **STEP 4 · 발송 검토** |
| ![자산 매칭 결과](docs/images/step3-matching.png) | ![부서별 발송 메시지 미리보기](docs/images/step4-review.png) |
| **CVE 데이터베이스 · 피드 반입** | **대시보드** |
| ![피드 적용 후 CVE DB](docs/images/cve-feed-applied.png) | ![대시보드](docs/images/dashboard.png) |
| **발송이력 · 조치관리 콘솔** | **내부 게시판(무인증)** |
| ![발송이력 콘솔](docs/images/history-console.png) | ![내부 게시판](docs/images/board.png) |

## 주요 기능

- **권고문 업로드와 CVE 추출** — PDF를 올리면 정규식으로 CVE 코드를 뽑고, 표가 있으면 표에서 제품·영향 버전·해결 버전을 먼저 읽습니다. 놓친 CVE나 제품은 화면에서 직접 추가·수정합니다.
- **로컬 CVE DB 조회** — 인터넷 없이 로컬 DB만 조회합니다. DB에 없는 CVE가 하나라도 있으면 서버가 자산 매칭을 막습니다(`409 NEEDS_CVE_UPDATE`).
- **CVE 피드 반입** — NVD(National Vulnerability Database) JSON(JavaScript Object Notation, 1.1·2.0), CSV(Comma-Separated Values), KISA(한국인터넷진흥원) KrCERT(Korea Computer Emergency Response Team) 형식 파일을 올려 검증한 뒤 적용합니다. 적용하면 미등록 CVE가 채워지고 미완료 권고문이 다시 처리됩니다.
- **자산관리대장 가져오기** — 엑셀 파일을 미리 보고 열 매핑을 고른 뒤 반영합니다. 여러 시트와 사용자 지정 필드를 지원합니다.
- **자산 매칭** — 제품 정규화 사전과 버전 비교기(`23H2`, `2021`, `124 미만`, `DC 2022` 등)로 영향 자산을 찾습니다. 오탐은 제외할 수 있고, 같은 자산·제품 조합은 다음 권고문에서 제외 후보로 표시됩니다.
- **부서별 발송** — 부서마다 메시지를 만들어 SMTP(Simple Mail Transfer Protocol) 메일, 메신저·그룹웨어 웹훅으로 보냅니다. 중복 발송은 멱등성 키로 막고, 실패는 `FAILED` 로 남깁니다.
- **조치 추적** — 부서별 회신(완료·진행중·불가), 증빙 파일, 기한 임박 리마인드, 엑셀·HTML(HyperText Markup Language) 보고서를 제공합니다.
- **내부 게시판(`/board`)** — 로그인 없이 사내 누구나 공개된 권고문을 보고 댓글로 조치 결과를 회신합니다. 회신은 발송 이력에 자동으로 반영됩니다.
- **관리자 인증** — 로그인, 최초 비밀번호 강제 변경, CSRF(Cross-Site Request Forgery) 토큰, 5회 실패 시 잠금, 감사 로그를 갖추고 있습니다.
- **폐쇄망 배포** — React와 글꼴을 저장소 안에 두어 외부 요청이 없고, 의존성은 오프라인 휠로만 설치합니다. Windows용 올인원 번들(임베디드 Python 포함)도 만들 수 있습니다.

## 사용 방법

### 1. 설치

Python 3.11 이상이 필요합니다. 폐쇄망 PC에 설치한다면 먼저 인터넷이 되는 PC(Personal Computer)에서 의존성 휠을 모읍니다(타깃과 같은 OS(Operating System)·CPU(Central Processing Unit)·Python 버전에서 실행).

```bash
./scripts/prepare_offline.sh        # Windows: scripts\prepare_offline.bat
```

`vendor/wheels/` 폴더가 생기면 프로젝트 폴더와 함께 폐쇄망 PC로 복사합니다.

### 2. 실행

```bash
chmod +x start.sh && ./start.sh     # Windows: start.bat
```

`start.*` 는 `.venv` 를 만들고 `vendor/wheels` 에서만 의존성을 설치한 뒤 `http://localhost:8000` 으로 서버를 띄웁니다. 개발 PC에서 PyPI(Python Package Index)로 바로 설치하려면 `ADVISORY_ONLINE_INSTALL=1 ./start.sh` 로 실행합니다.

데모 데이터로 둘러보려면 시드 옵션을 켭니다.

```bash
ADVISORY_SEED=true ./start.sh
```

설정은 `.env.example` 을 `.env` 로 복사해 바꿉니다(SMTP 서버, 웹훅 주소, 데이터 폴더 등).

### 3. 첫 로그인

1. 처음 기동하면 콘솔에 관리자 계정(`admin`)과 무작위 비밀번호가 한 번만 표시됩니다. `.env` 에 `ADVISORY_BOOTSTRAP_PASSWORD` 를 지정했다면 그 값을 씁니다.
2. `http://localhost:8000/admin` 에 접속해 로그인하면 비밀번호 변경 화면이 나옵니다. 바꾸기 전에는 다른 기능을 쓸 수 없습니다.

### 4. 권고문 처리 흐름

1. **권고문 처리** 메뉴에서 PDF를 올립니다. 업로드와 동시에 CVE 추출이 시작됩니다.
2. 목록에서 **처리 →** 를 누르면 STEP 2(CVE 추출·조회) 화면이 열립니다. DB 미등록 CVE가 있으면 경고가 표시됩니다.
3. **CVE 데이터베이스** 메뉴에서 피드 파일을 선택하고 **피드 적용 · DB 갱신** 을 누릅니다. 데모에서는 `samples/krcert_cve_feed_2026-06-15.json` 을 쓰면 미등록 2건이 해소됩니다.
4. STEP 3(자산 매칭)에서 결과를 확인하고 오탐을 제외합니다.
5. STEP 4(발송 검토)에서 부서별 메시지를 확인하고 발송합니다. SMTP가 설정되지 않았으면 `FAILED` 로 기록됩니다.
6. **게시판 게시** 를 누르면 `/board` 에 공개되고, 부서 담당자가 댓글로 조치 결과를 회신합니다.
7. **발송 이력** 메뉴나 `/admin/history` 콘솔에서 부서별 진행 상황을 보고, 미회신 부서에 재발송하거나 보고서를 내려받습니다.

API(Application Programming Interface) 문서는 서버 실행 후 `http://localhost:8000/docs` 에서 볼 수 있습니다.

### 5. 테스트

```bash
pip install -r requirements-dev.txt
pytest tests
python smoke_test.py
```

## 기술 스택

| 구분 | 내용 |
|---|---|
| 언어 | Python 3.11 이상(올인원 번들은 임베디드 Python 3.12.10 · 3.13.7), JavaScript |
| 백엔드 | FastAPI `>=0.111,<1.0`, Uvicorn `>=0.30,<1.0`, SQLAlchemy `>=2.0,<2.1`, Pydantic `>=2.6,<3.0`, python-multipart `>=0.0.9` |
| 문서 처리 | pypdf `>=4.2,<6.0`(텍스트), pypdfium2 `>=4.30,<5.0`(페이지 렌더링·표 좌표), openpyxl `>=3.1,<4.0`(엑셀) |
| 데이터베이스 | SQLite(기본, `data/advisory.db`) |
| 프론트엔드 | 빌드 없는 React 18.3.1 SPA(Single Page Application), Pretendard 글꼴 — 모두 `web/public/vendor/` 에 포함 |
| 테스트 | pytest `>=8.0`, httpx `>=0.27`, `smoke_test.py` |
| 배포 | `start.sh`/`start.bat`(오프라인 휠 설치), `build_allinone.py`(Windows amd64 올인원 zip·7z 분할) |
| 부가 도구 | `nvd_powershell_sync/`(PowerShell NVD 동기화), `.ds-build/`(Node.js·esbuild 기반 디자인 시스템 번들 생성) |

## 문서

- [진행 기록](docs/PROGRESS.md) — 최종 목표, 기능별 구현 상태, 작업 이력
- [상세 운영 가이드](docs/상세_운영_가이드.md) — 올인원 번들, 인증·파일 접근통제, REST(Representational State Transfer) API 목록, 환경변수, 표 추출 동작, 배포 체크리스트
- [구현 작업 기록](docs/구현_작업_기록.md)
- [대규모 개편안](docs/대규모_개편안.md)
- [보안 검토 보고서](docs/security-review.md)
- [테스트 가이드](docs/testing-guide.md)
- [NVD PowerShell 동기화 도구](nvd_powershell_sync/README-NVD-CVE-PowerShell-Sync.md)
- 화면 목업: `mockups/`, 디자인 시스템 번들: `ds-bundle/`
