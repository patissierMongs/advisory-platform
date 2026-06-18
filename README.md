# 보안권고문 처리 시스템

국정원·국토부 등에서 접수되는 **보안권고문(PDF) → CVE 추출 → 로컬 CVE DB 조회 → 자산 매칭 → 부서 발송**
워크플로우를 자동화하는 폐쇄망(인트라넷) 운영용 백엔드 + 웹 UI.

프로토타입(디자인 산출물)과 [백엔드 구현 명세서]를 그대로 구현했습니다. FastAPI + SQLAlchemy 백엔드와,
기존 DC 프론트엔드를 **실 백엔드에 연결**한 단일 SPA로 구성됩니다.

---

## 빠른 시작

```bat
:: Windows
start.bat
```
```bash
# Linux / Mac
chmod +x start.sh && ./start.sh
```
```bash
# 수동
python -m venv .venv && . .venv/Scripts/activate   # (Linux: source .venv/bin/activate)
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

브라우저에서 **http://localhost:8000** 접속 → 첫 부팅 시 프로토타입과 동일한 데이터가 자동 시드됩니다.

> 기본 DB는 **SQLite**(파일, 무설치)입니다. 운영(PostgreSQL)은 `ADVISORY_DATABASE_URL` 만 교체하면 됩니다
> (스키마는 SQLAlchemy 로 동일). 외부망/외부 API 호출은 0건입니다.

---

## 데모 시나리오 (시드 상태로 바로 재현)

1. **권고문 처리 · STEP 2** — 활성 권고문 `국정원-사이버-2026-0612` 의 CVE 6건 중 **2건이 "DB 미등록"**
   (한컴오피스/Acrobat). 서버 게이트에 의해 "자산 매칭" 진행이 막혀 있습니다.
2. **CVE 데이터베이스** 탭 → "파일 선택"으로 스테이징 → **"피드 적용"** 클릭. 프론트가 번들된
   `samples/krcert_cve_feed_2026-06-15.json` 을 업로드·적용 → 미등록 2건이 자동 해소 → 게이트 해제.
3. **STEP 3 자산 매칭** — 진입 시 서버 매칭 실행. 버전 비교기로 *Chrome 122.x/121.x < 124* 는 매칭,
   *Windows 10* 은 Windows 11 CVE에서 제외됩니다. 오탐 제외 토글 가능.
4. **STEP 4 발송** — 부서별 메시지 자동 생성 → 발송(멱등). 메신저/메일 게이트웨이 미연동 시
   `data/outbox.log` 에 적재(외부 호출 0).
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
├─ web/                  프론트엔드(DC SPA, 백엔드 연동)
│  ├─ app.dc.html        UI(템플릿 동일, 로직만 API 연동)
│  ├─ support.js         DC 런타임
│  └─ sample-feed.json   데모용 CVE 피드
├─ samples/              CVE 피드 샘플
├─ smoke_test.py         엔드투엔드 테스트(29건)
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
| **조치 진척** | `GET /advisories/:id/remediation` · `PATCH /notifications/:id/ack` (완료/진행중/불가+코멘트) · `POST /notifications/:id/evidence` |
| **보고서** | `GET /advisories/:id/report.xlsx` · `GET /advisories/:id/report.html` (인쇄→PDF) |
| **SLA·리마인드** | `GET /reminders/due` · `POST /advisories/:id/remind` |
| **CVE 보정** | `POST /advisories/:id/cves` · `DELETE /advisory-cves/:id` |
| **게시판·오탐기억** | `POST /advisories/:id/board` · `POST /webhooks/groupware/ack` · `GET /exclusion-rules` |
| 기타 | `GET /departments` · `GET /dashboard` (SLA·리마인드 요약) · `GET /api/health` |

대화형 문서: 서버 실행 후 **http://localhost:8000/docs** (Swagger).

## 두 개의 서버측 게이트(명세 §2.2 — 프론트 검증에 의존하지 않음)

- **미등록 CVE → 매칭 차단**: `POST /advisories/:id/match` 는 모든 CVE 가 `FOUND` 가 아니면 `409 NEEDS_CVE_UPDATE`.
- **발송은 명시 확인**: `POST …/notifications` 만이 발송을 실행하며 멱등성 키로 중복 발송을 방지.

## 설정(환경변수)

| 변수 | 기본값 | 설명 |
|---|---|---|
| `ADVISORY_DATABASE_URL` | `sqlite:///data/advisory.db` | 운영은 `postgresql+psycopg://…` |
| `ADVISORY_SEED` | `true` | 시작 시 데모 데이터 시드 |
| `ADVISORY_MESSENGER_ENABLED` / `ADVISORY_MAIL_ENABLED` / `ADVISORY_GROUPWARE_ENABLED` | `false` | 발신 채널 활성(미설정·실패 시 outbox·board.log 폴백 → 외부호출 0 유지) |
| `ADVISORY_MAIL_SMTP_HOST` `_PORT` `_USER` `_PASSWORD` `ADVISORY_MAIL_USE_TLS` `ADVISORY_MAIL_FROM` | (빈값)·`25` | 메일 = 표준 SMTP. 호스트 지정 시 실제 발송 |
| `ADVISORY_MESSENGER_WEBHOOK_URL` · `ADVISORY_GROUPWARE_WEBHOOK_URL` | (빈값) | 메신저·게시판 = 범용 웹훅 POST(JSON) |
| `ADVISORY_MAX_UPLOAD_MB` | `30` | 업로드 크기 제한 |

## 테스트

```bash
.venv/Scripts/python.exe smoke_test.py    # 게이트·피드·매칭·발송·업로드·임포트·어댑터 55건
```

---

## CVE 추출 (정규식)

CVE 식별자 추출은 **정규식 한 단계**로 결정적으로 처리합니다. 표준형 `CVE-YYYY-NNNN` 외에
PDF 표 추출 등에서 흔한 띄어쓰기·구분자 변형(`CVE 2026 21345`, `CVE_2026_21345`, 다중 공백)도
표준형으로 정규화해 함께 잡습니다(`core/extract.py`). 정규식이 놓치는 코드는 권고문 상세에서
**수동 추가**(`POST /advisories/:id/cves`)로 보정하며, 추가 즉시 게이트가 재평가됩니다.

## 폐쇄망 배포 시 체크리스트(명세 §7)

- [x] **완료** — React·ReactDOM·Pretendard 를 `web/vendor/` 로 로컬 번들링(외부 CDN 요청 0건, 브라우저 검증 완료).
      Babel 은 JSX x-import 미사용으로 호출되지 않음.
- [ ] DB 를 PostgreSQL 로(`ADVISORY_DATABASE_URL`), 원본 PDF/피드 저장소를 내부 스토리지로.

## 아직 외부 규격 확정이 필요한 부분(명세 §9 — 어댑터로 격리됨)

| 항목 | 현재 구현 | 확정 시 |
|---|---|---|
| 사내 메일 발송 | **표준 SMTP 구현 완료**(`notify._send_mail`) — `ADVISORY_MAIL_SMTP_HOST` 설정 시 발송, 미설정·실패 시 outbox 폴백 | (선택) 조직 메일 정책 반영 |
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

> 백엔드·API·서빙은 자동 검증 완료(스모크 55/55 + 어댑터 6/6). React UI 의 인터랙션은 브라우저에서
> `http://localhost:8000` 접속해 클릭 동선으로 최종 확인하세요.
