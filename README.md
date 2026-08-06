# 보안권고문 처리 시스템

국정원·국토부 등에서 접수되는 **보안권고문(PDF) → CVE 추출 → 로컬 CVE DB 조회 → 자산 매칭 → 부서 발송**
워크플로우를 자동화하는 폐쇄망(인트라넷) 운영용 백엔드 + 웹 UI.

프로토타입(디자인 산출물)과 [백엔드 구현 명세서]를 그대로 구현했습니다. FastAPI + SQLAlchemy 백엔드와,
기존 DC 프론트엔드를 **실 백엔드에 연결**한 단일 SPA로 구성됩니다.

---

## 빠른 시작

이 시스템은 **폐쇄망(인터넷 없음)** 운영을 기본 전제로 합니다. **실행 경로는 외부망을 절대 타지 않습니다.**
인터넷이 필요한 작업은 배포 준비 단계 한 곳(`prepare_offline` 또는 올인원 빌드)으로 격리했습니다.

**① 인터넷 되는 PC에서 한 번 — 의존성(휠) 수집**
```bat
:: Windows
scripts\prepare_offline.bat
```
```bash
# Linux / Mac
./scripts/prepare_offline.sh
```
→ `vendor/wheels/` 가 생성됩니다. **타깃과 동일한 OS/CPU/파이썬**에서 실행해야 바이너리 휠(pypdfium2 등)이 호환됩니다.

**② 폐쇄망 타깃 — 프로젝트 폴더(+`vendor/wheels`)를 복사 후 실행**
```bat
:: Windows
start.bat
```
```bash
# Linux / Mac
chmod +x start.sh && ./start.sh
```
`start.*` 는 `vendor/wheels` 에서 `--no-index` 로만 설치하므로 **PyPI/인터넷에 접속하지 않습니다**.
(개발 PC에서 굳이 PyPI로 온라인 설치하려면 `ADVISORY_ONLINE_INSTALL=1` 을 명시해야 합니다.)

> **대안 — 올인원 번들**: `python build_allinone.py` 로 임베디드 Python + 의존성까지 포함한 zip을 만들면,
> 타깃은 Python 설치도 `vendor/wheels` 준비도 없이 압축만 풀고 `start.bat` 으로 바로 실행합니다(외부망 0).

브라우저에서 **http://localhost:8000** 접속 → 기본 실행은 운영 기준으로 빈 SQLite DB에서 시작합니다.

> 기본 DB는 **SQLite**(파일, 무설치)입니다. 내부 관리자용 운영도 SQLite 파일 구조를 그대로 유지하는 것을 기본 전제로 합니다.
> 기존 `data/` 가 있다면 운영 시작 전 백업하거나 초기화하세요. 데모 데이터는 `ADVISORY_SEED=true` 를 명시한 경우에만 넣습니다.

---

## 데모 시나리오 (필요할 때만)

데모 데이터가 필요하면 실행 전에 `ADVISORY_SEED=true` 를 지정하세요.

1. **권고문 처리 · STEP 2** — 활성 권고문 `국정원-사이버-2026-0612` 의 CVE 6건 중 **2건이 "DB 미등록"**
   (한컴오피스/Acrobat). 서버 게이트에 의해 "자산 매칭" 진행이 막혀 있습니다.
2. **CVE 데이터베이스** 탭 → "파일 선택"에서
   `samples/krcert_cve_feed_2026-06-15.json` 을 직접 선택해 스테이징 → **"피드 적용"** 클릭.
   미등록 2건이 자동 해소 → 게이트 해제.
3. **STEP 3 자산 매칭** — 진입 시 서버 매칭 실행. 버전 비교기로 *Chrome 122.x/121.x < 124* 는 매칭,
   *Windows 10* 은 Windows 11 CVE에서 제외됩니다. 오탐 제외 토글 가능.
4. **STEP 4 발송** — 부서별 메시지 자동 생성 → SMTP 메일 + 내부 기록 발송(멱등).
   SMTP 미설정 또는 실패는 `FAILED` 로 기록되며 `SENT` 로 취급하지 않습니다.
5. **발송 이력 / 대시보드** — 발송·회신 현황 집계.

---

## 구조

```
advisory-platform/
├─ app/
│  ├─ main.py            FastAPI 앱(라우터·정적 서빙·시작 시 시드)
│  ├─ config.py          설정(env 오버라이드)
│  ├─ db.py models.py    엔진/세션 · 데이터 모델(명세 §3)
│  ├─ enums.py schemas.py serializers.py
│  ├─ core/              핵심 로직(명세 §4)
│  │  ├─ extract.py      PDF 텍스트 + CVE 정규식(변형 정규화)
│  │  ├─ feeds.py        NVD/CSV/내부 피드 파서 + upsert
│  │  ├─ normalize.py    제품 정규화 사전(product_key)
│  │  ├─ versioning.py   버전 비교기(23H2 / 2021 / 124 / DC 2022)
│  │  ├─ matching.py     매칭 엔진(제품키 + 버전 규칙)
│  │  ├─ assets_import.py 엑셀 미리보기·추천매핑·커밋
│  │  └─ notify.py       메시지 생성 · 채널 어댑터 · 멱등성
│  ├─ routers/           REST API(명세 §5)
│  └─ seed.py            프로토타입 데이터 시드
├─ web/
│  ├─ public/            /ui 로 정적 서빙되는 공개 자산
│  │  ├─ board.html      내부 게시판(무인증)
│  │  ├─ login.html      관리자 로그인 · 비밀번호 변경
│  │  ├─ support.js      DC 런타임
│  │  └─ vendor/         React·ReactDOM·Pretendard(동일 출처, 외부 요청 0건)
│  └─ admin/             정적 마운트에 없음 — /admin 라우트가 세션 확인 후 서빙
│     ├─ app.dc.html     관리자 SPA(템플릿 동일, 로직만 API 연동)
│     └─ history.html    발송이력·조치관리 콘솔
├─ samples/              CVE 피드 샘플
├─ smoke_test.py         엔드투엔드 테스트
└─ requirements.txt start.bat start.sh
```

## REST API (요약, 접두사 `/api/v1`)

| 도메인 | 엔드포인트 |
|---|---|
| 권고문 | `POST /advisories` · `POST /advisories/:id/extract` · `GET /advisories/:id/cves` · `GET /advisories/:id/file` |
| CVE 피드 | `POST /cve-feeds` → `POST /cve-feeds/:id/apply` · `GET /cve-feeds` |
| CVE DB | `GET /cves` · `GET /cves/stats` |
| 자산 | `GET /assets` · `POST /assets/import/preview` → `:id/commit` |
| 매칭 | `POST /advisories/:id/match` · `GET /advisories/:id/matches` · `PATCH /matches/:id` |
| 발송 | `GET /advisories/:id/notification-preview` · `POST /advisories/:id/notifications` · `GET /notifications` |
| 발송 진단 | `GET /notify/status` · `POST /notify/test` |
| **조치 진척** | `GET /advisories/:id/remediation` · `PATCH /notifications/:id/ack` (완료/진행중/불가+코멘트) · `POST /notifications/:id/evidence` |
| **보고서** | `GET /advisories/:id/report.xlsx` · `GET /advisories/:id/report.html` (인쇄→PDF) |
| **SLA·리마인드** | `GET /reminders/due` · `POST /advisories/:id/remind` |
| **CVE 보정** | `POST /advisories/:id/cves` · `DELETE /advisory-cves/:id` |
| **게시판 공개·오탐기억** | `POST /advisories/:id/board`(내부 게시판 공개) · `POST /advisories/:id/board-unpublish` · `POST /webhooks/groupware/ack` · `GET /exclusion-rules` |
| **내부 게시판(무인증)** | `GET /board/advisories`(검색 `?q=`·`?exclude_done=`) · `GET /board/advisories/:id` · `GET /board/advisories/:id/file`(원문 PDF) · `POST /board/advisories/:id/comments` · `POST /board/advisories/:id/asset-ack` · `POST /board/comments/:id/evidence` · `GET /board/departments` |
| **게시판 중 관리자 전용** | `DELETE /board/comments/:id`(모더레이션) · `GET /board/comments/:id/evidence`(증빙 열람) |
| **인증** | `POST /auth/login` · `POST /auth/logout` · `GET /auth/me` · `POST /auth/password` · `GET/POST /auth/users` · `PATCH /auth/users/:id` · `POST /auth/users/:id/password-reset` |
| 웹훅(HMAC 서명) | `POST /webhooks/groupware/ack` |
| 기타 | `GET /departments` · `GET /dashboard` (SLA·리마인드 요약) · `GET /api/health`(무인증) |

> **위 표에서 "무인증"·"웹훅"으로 표시된 것을 제외한 전 엔드포인트는 관리자 로그인이 필요합니다**(미인증 시 401).
> 상태변경 요청(POST/PATCH/DELETE)에는 `X-CSRF-Token` 헤더가 필요합니다 — 값은 로그인 시 내려오는 `adv_csrf` 쿠키에 있습니다.

대화형 문서: 서버 실행 후 **http://localhost:8000/docs** (Swagger).

## 화면 두 갈래 — 관리자 / 내부 게시판

- **`/admin`** — 기존 SPA. 관제 인원이 권고문 업로드·CVE 추출·자산 매칭·발송·조치추적을 수행. **로그인 필요**(미인증 시 로그인 화면으로 이동).
  - **발송 이력 탭** — 권고문별 마스터/디테일(부서별 조치현황·신규 댓글 배지·조치불가 사유·보고서 모달·리마인드).
  - **`/admin/history`** — 발송이력·조치관리 **독립 콘솔**(권고문별/부서별 피벗 · 발송 문구 프리셋 · 미회신 부서 재발송). 발송 이력 탭의 "조치관리 콘솔 ↗"로 연결.
- **`/board`** — 사내 누구나(무인증) 들어와 **공개된 보안권고문을 게시글처럼 열람하고 댓글로 회신**하는 내부 게시판. 루트 `/` 는 게시판으로 이동.
  - 관리자가 권고문 상세에서 **"게시판 게시"** 를 누르면 게시판에 공개됨(`board-unpublish` 로 내림).
  - 각 권고문은 **영향 부서·자산·담당자(매칭 결과)** 를 한눈에 보여줌 — 목록 카드에 영향 부서 칩(담당자)·제품 요약, 상세에 부서별 자산·담당자 표.
  - 상단 **검색(자산번호·담당자명·부서명·제목)** + **"완료 제외"(기본 체크)**.
  - 상세에서 **원문 PDF 열람**(새 탭 / 인라인).
  - 댓글은 **부서(검색 드롭다운 / 직접입력) + 이름**으로 작성. **조치상태(완료/진행중/불가)** 를 첨부하면 해당 부서의 발송 **ack 로 자동 동기화**(자유 댓글 + 공식 회신 겸용).
  - 외부 그룹웨어 연동 없이 **이 시스템 자체가 게시판** 역할(폐쇄망 내부 공유).

## 관리자 로그인 · 파일 접근통제

### 최초 기동

1. 서버를 처음 띄우면 **관리자 계정이 자동 생성**되고 콘솔에 출력됩니다.
   `.env` 에 `ADVISORY_BOOTSTRAP_PASSWORD` 를 넣지 않았다면 **무작위 비밀번호가 이 화면에만 1회 표시**되므로,
   `start.bat` 창을 닫기 전에 받아 적으세요. (코드베이스에 기본 비밀번호를 두지 않기 위한 설계입니다.)
   ```
   [auth] 초기 관리자 계정 생성: admin
   [auth] 초기 비밀번호(이 화면에만 1회 표시): xxxxxxxxxxxx
   ```
2. `/admin` 접속 → 로그인 → **비밀번호 변경이 강제**됩니다(변경 전에는 어떤 관리자 기능도 쓸 수 없습니다).
3. 이후 계정 추가·비활성화·비밀번호 초기화는 관리자 화면에서 할 수 있습니다.

비밀번호를 분실했다면 `.env` 의 `ADVISORY_BOOTSTRAP_ADMIN` 계정을 DB 에서 지우고 재기동하면 다시 발급됩니다.

### 무엇이 열려 있고 무엇이 닫혀 있나

| 대상 | 접근 |
|---|---|
| 내부 게시판(`/board`, 열람·댓글·조치회신·증빙 **업로드**) | **무인증** — 기존 설계 유지 |
| 관리자 화면(`/admin`, `/admin/history`)과 그 API 전부 | 로그인 필요 |
| 댓글 **삭제**, 댓글 증빙 **열람** | 로그인 필요(게시판 화면에서 증빙은 원래 숨겨져 있었습니다) |
| 그룹웨어 ack 웹훅 | HMAC 서명(`ADVISORY_WEBHOOK_SECRET`). 시크릿 미설정 시 503 |

로그인 실패 5회 시 15분 계정 잠금, 세션은 12시간(유휴 60분) 후 만료됩니다.

### 업로드 파일 접근통제 (Windows)

업로드물(`data/uploads`, `data/evidence`, `data/feeds`, `data/assets`)은 정적 서빙 경로 밖에 있으며,
**API 를 통해서만** 나갑니다. 그중 증빙 파일은 관리자 인증이 있어야 열람됩니다.
`ADVISORY_DATA_DIR` 이 `web/` 안을 가리키면 업로드물이 통째로 노출되므로 **기동이 거부**됩니다.

디스크 레벨에서는 최초 기동 시 `data` 폴더에 **NTFS ACL** 을 적용합니다(상속 제거 + SYSTEM·Administrators·구동 계정만 허용).
폴더를 옮겼거나 백업에서 복원했거나 구동 계정이 바뀌었다면 `scripts\harden_data_acl.bat` 로 다시 적용하세요.
적용 상태는 `icacls data` 로 확인할 수 있습니다 — `BUILTIN\Users` 항목이 없어야 정상입니다.

> **한계 — 반드시 알고 계셔야 합니다.**
> 운영자 계정으로 `start.bat` 을 직접 실행하는 구성에서 이 ACL 은 **일반 사용자와 네트워크 공유 접근을 차단**합니다.
> 그러나 **같은 PC 의 다른 로컬 관리자는 소유권을 획득해 여전히 파일을 읽을 수 있습니다.**
> 그 이상이 필요하면 (a) 전용 저권한 서비스 계정으로 구동하고 ACL 을 그 계정으로 좁히거나,
> (b) EFS/앱단 암호화를 도입해야 합니다. 현재 범위에는 포함돼 있지 않습니다.
> 또한 `data/advisory.db` 자체는 암호화돼 있지 않으므로, 백업본을 옮길 때는 백업 매체 쪽 보호가 필요합니다.

## 두 개의 서버측 게이트(명세 §2.2 — 프론트 검증에 의존하지 않음)

- **미등록 CVE → 매칭 차단**: `POST /advisories/:id/match` 는 모든 CVE 가 `FOUND` 가 아니면 `409 NEEDS_CVE_UPDATE`.
- **발송은 명시 확인**: `POST …/notifications` 만이 발송을 실행하며 멱등성 키로 중복 발송을 방지.

## 설정(환경변수)

`.env.example` 을 `.env` 로 복사해 값을 채우면 앱 시작 시 자동으로 읽습니다. 실제 `.env` 는 `.gitignore` 대상입니다.

| 변수 | 기본값 | 설명 |
|---|---|---|
| `ADVISORY_DATABASE_URL` | `sqlite:///data/advisory.db` | 기본 SQLite 파일 DB 유지. 필요 시 데이터 파일 위치만 조정 |
| `ADVISORY_SEED` | `false` | 시작 시 데모 데이터 시드. 데모가 필요할 때만 `true` |
| `ADVISORY_BUNDLED_FEEDS` | `false` | `samples/cve_feeds/` 자동 적재. 운영은 실제 피드 파일을 화면에서 검증 후 적용 |
| `ADVISORY_MAIL_ENABLED` | `true` | SMTP 메일 채널 활성. SMTP host 미설정·실패는 `FAILED` |
| `ADVISORY_MESSENGER_ENABLED` / `ADVISORY_GROUPWARE_ENABLED` | `false` | 메신저·그룹웨어 웹훅 활성. 미설정·실패는 실패로 기록 |
| `ADVISORY_MAIL_SMTP_HOST` `_PORT` `_USER` `_PASSWORD` `ADVISORY_MAIL_USE_TLS` `ADVISORY_MAIL_FROM` | (빈값)·`25` | 메일 = 표준 SMTP. 비밀번호는 환경변수로만 관리하며 UI/DB에 저장하지 않음 |
| `ADVISORY_MESSENGER_WEBHOOK_URL` · `ADVISORY_GROUPWARE_WEBHOOK_URL` | (빈값) | 메신저·게시판 = 범용 웹훅 POST(JSON) |
| `ADVISORY_MAX_UPLOAD_MB` | `30` | 업로드 크기 제한 |

## 테스트

```bash
.venv/Scripts/python.exe smoke_test.py    # 게이트·피드·매칭·발송·업로드·임포트·어댑터 66건
pytest tests
```

---

## CVE 추출 (정규식)

CVE 식별자 추출은 **정규식 한 단계**로 결정적으로 처리합니다. 표준형 `CVE-YYYY-NNNN` 외에
PDF 표 추출 등에서 흔한 띄어쓰기·구분자 변형(`CVE 2026 21345`, `CVE_2026_21345`, 다중 공백)도
표준형으로 정규화해 함께 잡습니다(`core/extract.py`). 정규식이 놓치는 코드는 권고문 상세에서
**수동 추가**(`POST /advisories/:id/cves`)로 보정하며, 추가 즉시 게이트가 재평가됩니다.

## 제품·버전 추출 — 표 우선

권고문의 주 서식은 표입니다. **표에서 먼저 뽑고, 표가 아니면 본문 정규식으로 떨어집니다.**

| 취약점 | 제품명 | 영향받는 버전 | 해결 버전 |
|---|---|---|---|
| CVE-2026-8461 | FFmpeg | 8.1.0 이상 8.1.2 미만 | 8.1.2 |
| CVE-2026-8461 | FFmpeg | 8.0.0 이상 8.0.3 미만 | 8.1.3 |

### 지원하는 서식

- **열 구성** — `취약점 | 제품명 | 영향받는 버전 | 해결 버전`. 열 이름은 표기 변형을 폭넓게 인식합니다
  (제품/대상 제품/영향 제품, 취약 버전/대상 버전, 조치·패치·업데이트 버전, 영문 Product/Affected/Fixed 등).
  **제품명과 영향받는 버전 두 열만 있으면** 표로 인정하므로 취약점·해결 열이 없는 3열 표도 처리합니다.
  심각도 등 여분 열은 무시합니다.
- **영향받는 버전** — 두 경계 범위(`8.1.0 이상 8.1.2 미만`, `3.0.0 ~ 3.0.14`, `A 부터 B 까지`,
  영문 `A to B`), 한쪽 경계(`9.0.90 미만`, `124 이하`, `10.1.25 이상`), 단일·다중 버전(`22H2, 23H2`).
- **해결 버전** — 단일 또는 다중(`9.0.90, 10.1.25`).
- **한 제품에 여러 행** — 위 예시처럼 같은 제품에 범위가 여럿이면 모두 보존합니다.
  화면에는 `FFmpeg 8.1.0~8.1.2 또는 8.0.0~8.0.3` 처럼 표시되고, 자산 매칭도 두 범위 모두에 대해 동작합니다.
- **병합셀** — 취약점·제품명 칸이 병합돼 비어 있으면 위 행의 값을 물려받습니다.
- **여러 페이지에 걸친 표**, 셀 안 줄바꿈, 표 위·아래 산문도 처리합니다.

### 표가 아니거나 읽지 못한 경우

권고문 목록 카드에 **색과 배지로 표시**되어 관리자가 보정 대상을 바로 찾을 수 있습니다.

| 표시 | 뜻 | 대응 |
|---|---|---|
| 🟡 `표 형태 아님` | 제품·버전 표를 찾지 못함(산문형 공지 등) | 본문 정규식 결과를 확인하고 권고문 상세에서 제품·버전을 직접 추가·수정 |
| 🟠 `표 인식 실패` | 표는 있으나 제품·버전 행을 읽지 못함 | 위와 동일. 원문 PDF를 열어 서식 확인 |

해석할 수 없는 버전 문구(`특정 버전으로 마이그레이션`, 비숫자 버전)는 **버리지 않고**
'전체 버전'으로 두고 원문을 근거 스니펫에 남깁니다 — 조용히 사라지면 대상이 없는 것으로 오해되기 때문입니다.

> **한계** — 스캔본(이미지) PDF는 문자 정보가 없어 표를 읽을 수 없습니다(OCR 미지원, `표 형태 아님`으로 표시).
> 셀 괘선이 아니라 텍스트 배치로 열을 판단하므로, 열 간격이 지나치게 좁거나 셀이 여러 열에 걸친
> 비정형 표는 인식률이 떨어질 수 있습니다. 추출 구현은 `app/core/pdf_tables.py`(좌표 복원) +
> `app/core/product_extract.py`(버전 구문 해석)입니다.

## 폐쇄망 배포 시 체크리스트(명세 §7)

- [x] **완료** — React·ReactDOM·Pretendard·Babel 모두 `web/public/vendor/`(동일 출처)에서만 로드. 외부 CDN(unpkg) 폴백 제거 →
      `support.js` 가 어떤 경우에도 외부망으로 나가지 않음(외부 요청 0건).
- [x] **완료** — 의존성 설치를 오프라인 휠(`vendor/wheels`)로 전환. `start.sh`/`start.bat` 는 `--no-index` 로만 설치하며
      기본 경로에서 PyPI/인터넷에 접속하지 않음. 휠 수집은 온라인 PC에서 `scripts/prepare_offline.*` 한 번.
- [ ] 운영 시작 전 `data/` 백업 또는 초기화 후 `ADVISORY_SEED=false` 로 기동.
- [ ] **최초 기동 콘솔에 출력된 초기 관리자 비밀번호를 확보하고, 로그인 후 즉시 변경**(변경 전에는 기능이 잠깁니다).
- [ ] **`icacls data` 로 접근 제한 확인** — `BUILTIN\Users` 항목이 없어야 함. 없으면 `scripts\harden_data_acl.bat` 실행.
      다른 표준 사용자 계정으로 `type data\evidence\*` 가 거부되는지 실제로 확인해 보면 확실합니다.
- [ ] `ADVISORY_DATA_DIR` 을 앱 폴더 밖 절대경로(예: `C:\advisory-platform-data`)로 두면 ACL 관리가 더 단순합니다.
- [ ] `ADVISORY_CORS_ORIGINS` 는 비워 둘 것(동일 출처 전용). 쿠키 인증과 `*` 는 함께 쓸 수 없어 기동이 거부됩니다.
- [ ] 그룹웨어 ack 웹훅을 쓴다면 `ADVISORY_WEBHOOK_SECRET` 설정 — 미설정 시 해당 엔드포인트는 503 으로 닫힙니다.
- [ ] SMTP 환경변수 설정 후 관리자 화면의 테스트 메일로 발송 확인.
- [ ] CVE 피드와 자산대장은 실제 파일을 화면에서 검증 후 적용.

## 아직 외부 규격 확정이 필요한 부분(명세 §9 — 어댑터로 격리됨)

| 항목 | 현재 구현 | 확정 시 |
|---|---|---|
| 사내 메일 발송 | **표준 SMTP 구현 완료**(`notify._send_mail`) — SMTP 성공만 `SENT`, 미설정·실패는 `FAILED` | (선택) 조직 메일 정책 반영 |
| 사내 메신저·그룹웨어 게시판 | **범용 웹훅 POST 구현 완료**(`notify._post_webhook`·`groupware.post_board`) — `*_WEBHOOK_URL` 설정 시 발신, 미설정·실패 시 outbox·board.log 폴백 | (선택) 비표준 API면 어댑터 1곳만 교체 |
| CVE 피드 정밀 스키마 | NVD JSON / CSV / 내부 JSON 파서 | 실제 피드 필드 고정 |
| 제품 정규화 사전 | `core/normalize.py` 별칭 사전 | 자산대장 실제 표기 반영 |

발신 어댑터(메일·메신저·게시판)는 **표준 프로토콜로 구현 완료**되어 설정만으로 동작하고, 나머지 항목도
**인터페이스 뒤에 격리**되어 나머지 시스템을 막지 않습니다.

## 프론트엔드 연동 방식

UI 템플릿은 프로토타입과 **100% 동일**합니다. 변경은 로직 클래스의 데이터 출처뿐:
하드코딩 메서드(`cveDb()`/`assets()`/`extractedCves()`/`advisory()`/이력·대시보드)가
`componentDidMount` 에서 로드한 **실 API 데이터**를 읽도록 바뀌었고, 사용자 액션(피드 적용·매칭 진입·
오탐 제외·발송)은 서버에 반영됩니다. 표현(스타일) 계산 코드는 그대로 재사용됩니다.

> 백엔드·API·서빙은 자동 검증 완료(스모크 66건 + pytest 66건). React UI 의 인터랙션은 브라우저에서
> `http://localhost:8000` 접속해 클릭 동선으로 최종 확인하세요.
