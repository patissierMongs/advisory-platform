# 보안 검증 보고서 — advisory-platform

> 작성일: 2026-06-22
> 검토 범위: 백엔드(FastAPI 라우터·코어), 프론트엔드(board/admin/history HTML + support.js),
> PowerShell 동기화 스크립트, 빌드/배포 스크립트, 시드·샘플 데이터 전체.
> 목적: 악성코드·개인정보(PII) 포함 전체 보안 검토.

---

## 1. 핵심 결론

| 항목 | 판정 | 근거 요약 |
|---|---|---|
| **악성코드·백도어** | ✅ 없음 | 리버스셸·데이터유출·크리덴셜 탈취·크립토마이너·난독화·download-and-execute 패턴 전무. 외부 통신은 전부 정상 출처(NVD `nvd.nist.gov`, CISA `cisa.gov`, `python.org`), 전부 HTTPS. NVD `.gz`는 다운로드 후 SHA256 검증. |
| **개인정보(PII)·비밀정보** | ✅ 실데이터 없음 | 시드·샘플·목업 모두 합성 데이터(홍길동, 010-1234-5678, 김샘플, 사설 IP 10.x). 주민번호·실이메일·실공인IP·개인키·API키·토큰 0건. 모든 자격증명은 환경변수로만 주입. |

악성코드·개인정보 측면은 깨끗하다. 다만 **애플리케이션 보안 취약점**이 다수 존재한다(아래 §3~§5).

---

## 2. 구조적 배경

~~전 엔드포인트가 **무인증**이다.~~ → **✅ 해소(관리자 로그인 도입).**
게시판(`/api/v1/board/*`)은 사내 공개라는 의도된 설계를 유지하되, 관리자 표면 전체(11개 라우터,
68개 엔드포인트)에 세션 게이트를 걸었다. 아래 H-1·H-2·H-3·H-7 은 이 변화로 함께 닫혔다.
게이트 누락을 막기 위해 OpenAPI 스키마를 순회해 공개 allowlist 밖 경로가 전부 401 인지
확인하는 회귀 테스트(`tests/test_authz_matrix.py`)를 함께 둔다.

---

## 3. High — 우선 조치 권장

### H-1. 증빙파일 저장형 XSS + 파일 IDOR
- 위치: `app/routers/board.py:492-539`, `app/routers/notifications.py:195-227`
- 내용:
  - 무인증으로 누구나 증빙파일 업로드 가능한데 **콘텐츠 타입 검증이 없음**.
  - 다운로드 시 `Content-Disposition: inline` + `media_type` 미지정 → `.html`/`.svg` 업로드 후
    동일 출처 inline 렌더 = 관리자 대상 **저장형 XSS**.
  - `GET /comments/{id}/evidence`·`/notifications/{id}/evidence`는 정수 ID만 바꾸면
    **모든 증빙파일 열람 가능**(권한 검증 없음, IDOR). README는 "게시판에서 증빙 비노출"이라 했으나
    이 엔드포인트는 그대로 서빙한다.
- 권고: 업로드 확장자/콘텐츠 타입 화이트리스트, 다운로드를 `Content-Disposition: attachment` +
  `X-Content-Type-Options: nosniff` 로 변경, 게시판 공개 범위에 맞춘 접근 제어.
- ✅ **조치 완료**:
  · 업로드 확장자 화이트리스트(`core/files.py: check_evidence_upload`) — `.html`/`.svg`/`.js` 는 저장 자체를 거부.
    매직바이트를 아는 형식은 내용까지 대조해 `evil.png` 안에 HTML 을 넣는 우회도 차단. 클라이언트
    `content_type` 은 판단 근거로 쓰지 않는다.
  · `GET /board/comments/{id}/evidence` 를 관리자 전용으로 전환(IDOR 해소). 게시판 응답은 이미
    `_public_comment` 가 증빙을 제거하고 있었으므로 화면의 공개 범위와 일치시킨 것이다.
  · **추가 발견·조치** — 덮어쓰기 구멍: 익명 POST 하나로 임의 댓글의 증빙을 갈아치우고, 연결된
    발송이력 `ack_evidence_path` 까지 재지정해 **부서 공식 조치증빙을 위조**할 수 있었다.
    이미 증빙이 있는 댓글은 409 로 거부하고, 파일명에 난수를 넣어 디스크상 덮어쓰기를 없앴다.
  · 두 PDF 엔드포인트·페이지 PNG·HTML 보고서에 `nosniff` 추가. 페이지 PNG 의 `Cache-Control` 은
    관리자 게이트 뒤 콘텐츠이므로 `public` → `private`.

### H-2. 무인증 댓글 삭제
- 위치: `app/routers/board.py:542` (`DELETE /comments/{id}`)
- 내용: 주석은 "관리자 화면에서만 호출"이라 명시하나 **실제 권한 검증이 전혀 없음**.
  네트워크상 누구나 임의 댓글(=공식 회신) 삭제 가능.
- 권고: 관리자 인증/토큰 게이트 추가.
- ✅ **조치 완료**: `dependencies=[Depends(require_admin)]`. 관리자 전용이 됐으므로 삭제자를
  감사 로그에 남긴다(이전에는 `actor_id=None`).

### H-3. 무인증 임의 메일 발송
- 위치: `app/routers/notifications.py:160-162` (`POST /notify/test`)
- 내용: 임의 주소로 SMTP 메일 발송 가능. 메일 남용/스팸 중계 발판.
- 권고: 관리자 전용 게이트, 수신 도메인 제한.
- ✅ **조치 완료(게이트)**: notifications 라우터 전체가 관리자 전용이 되어 무인증 발송이 불가능하다.
  · 잔여 권고: 수신 도메인 화이트리스트는 미도입(조직 메일 정책 확정 후).

### H-4. 서명 없는 그룹웨어 ack 웹훅
- 위치: `app/routers/remediation.py:137-160` (`POST /webhooks/groupware/ack`)
- 내용: 시크릿/서명 검증 없이 누구나 임의 부서의 **보안조치를 "완료(DONE)"로 위조** 가능.
  보안 조치현황 무결성 훼손.
- 권고: 공유 시크릿 또는 HMAC 서명 검증.
- ✅ **조치 완료**: `app/routers/webhooks.py` 로 분리 후 HMAC-SHA256 서명 검증
  (`X-Advisory-Timestamp` + `X-Advisory-Signature`, raw body 대상, 시계 오차 300초 초과 거부).
  시크릿 미설정은 무인증 허용이 아니라 **503(fail closed)** — 설정을 빠뜨린 배포가 조용히
  무방비로 뜨지 않게 했다. URL 은 그대로다.

### H-5. 압축폭탄(decompression bomb) / 메모리 DoS
- 위치: `app/core/feeds.py:294-329` (← `app/routers/cve_feeds.py:55-57,105-106`)
- 내용: `1f8b` 매직이면 자동 `gzip.open`, **해제 크기 상한 없음** + 업로드 크기 제한 없음.
  수MB `.gz`가 수GB로 팽창 → 디스크/메모리 고갈. 닫히지 않는 JSON 배열 요소도 무한 버퍼 증가(OOM).
- 권고: 카운팅 리더로 해제 바이트 상한, 업로드 크기 제한, per-element 버퍼 상한.

### H-6. 생성 리포트 수식 인젝션(XLSX formula injection)
- 위치: `app/core/reports.py:39-122` (`build_excel`)
- 내용: `owner_name`·`ip`·`product_raw`·`version_raw`·`ack_note`·`ack_by`·CVE `product`/`desc`/`source` 등
  미신뢰 입력을 `.xlsx` 셀에 그대로 기록. `=`/`+`/`-`/`@` 로 시작하면 검토자가 파일 열 때
  수식 평가(잠재적 DDE 명령 실행).
- 권고: 문자열 셀 앞에 `'` 프리픽스 또는 선두 `= + - @ \t \r` 정제.

### H-7. 무인증 부서 정보 변경
- 위치: `app/routers/departments.py:26-41`
- 내용: 부서 `email`/`messenger_id`를 누구나 변경 가능 → 향후 권고문 발송(자산·담당자 PII 포함)을
  **공격자 주소로 리다이렉트** 가능.
- 권고: 관리자 인증 게이트.
- ✅ **조치 완료**: departments 라우터 전체 게이트. 게시판은 자체 `/api/v1/board/departments` 를
  쓰므로 사내 사용자 동선에 영향이 없다(소비자 0건 확인).

---

## 4. Medium

### M-1. openpyxl 메모리 DoS (자산 임포트)
- 위치: `app/core/assets_import.py:84-109` (`_load_sheet`)
- `read_only=False`로 전체 시트를 list-of-lists로 복사 + 병합범위 forward-fill, 행/셀 상한 없음.
  악성 `.xlsx`(거대 dimension/shared strings)로 OOM 가능. 관리자 대면이라 H보다 낮음.
- 권고: 최대 셀 수 가드, 업로드 크기 제한, 기존 `tests/test_assets_import_safety.py`의 oversized 케이스 커버 확인.

### M-2. CORS 와일드카드 기본값
- 위치: `app/main.py:89-94`
- `allow_origins=["*"]` + 모든 메서드/헤더. credentials 미허용이라 영향은 제한적이었으나,
  **쿠키 세션을 도입하는 순간 악용 가능해진다**(모든 사이트가 사용자의 관리자 세션으로 API 호출).
- ✅ **조치 완료**: 기본값을 동일 출처(빈 목록 → CORSMiddleware 미부착)로 바꾸고, 값이 있을 때만
  `allow_credentials=True` + 메서드/헤더 한정. `*` 가 설정되면 **기동을 거부**한다.

### M-3. 폐쇄망 주장 위배 — CDN 폴백  ✅ 조치 완료
- 위치: `web/support.js`
- 내용(조치 전): 로컬 vendor 로드 실패 시 `unpkg.com`에서 React/ReactDOM/Babel을 재요청. Babel은 SRI 없음.
  README의 "외부 요청 0건" 보장이 코드상 깨질 수 있었음.
- 조치: `REACT_URL`/`REACT_DOM_URL`/`BABEL_URL` 을 모두 동일 출처 `./vendor/...` 로 교체.
  외부 CDN 폴백 제거 → `support.js` 가 어떤 경우에도 외부망으로 나가지 않음(`grep` 검증: web/ 외부 URL 0건).

### M-4. 설치 경로의 인터넷 의존 — 폐쇄망 전제 위배  ✅ 조치 완료
- 위치: `start.sh`, `start.bat`, `requirements.txt`
- 내용(조치 전): 문서화된 빠른 시작(`start.sh`/`start.bat`)이 `pip install -r requirements.txt` 로
  PyPI(인터넷)에서 의존성을 받았음. 폐쇄망 타깃에서 직접 실행 시 실패. 공급망 측면에서도 범위 지정·해시 미핀.
- 조치:
  · `start.*` 를 **오프라인 우선**으로 변경 — 로컬 휠 `vendor/wheels` 에서 `--no-index` 로만 설치.
    PyPI 온라인 설치는 `ADVISORY_ONLINE_INSTALL=1` 을 명시해야만 동작.
  · 온라인이 필요한 휠 수집 단계를 `scripts/prepare_offline.{sh,bat}` 한 곳으로 격리(인터넷 PC에서 1회).
  · README 빠른 시작을 오프라인 경로 우선으로 정리. `vendor/wheels/` 는 `.gitignore`(플랫폼별 재생성).
- 잔여 권고: 재현성·무결성을 더 높이려면 `pip-compile` 등으로 **버전 고정 + 해시 락파일**(`--require-hashes`) 도입.

---

## 5. Low / Informational

- **예외 원문 노출**: `app/routers/assets.py:69`, `cve_feeds.py:61`, `advisories.py:313`, `advisories.py:163`
  — 내부 경로/라이브러리 내부 정보 누출 소지. 권고: 일반화된 메시지로 치환.
- **헤더 인젝션 소지**: `app/routers/notifications.py:209,225` — `Content-Disposition`에 원본 파일명 미정제.
- **인라인 핸들러 따옴표**: `web/history.html:198` — `onclick` 내 부서명에 `esc()`가 작은따옴표 미이스케이프.
  실제 XSS는 `<`가 이스케이프되어 둔화되나 견고성 결함. 권고: JSON 인코딩/`encodeURIComponent`.
- **이넘 값 무이스케이프 보간**: `web/board.html:128,319`, `web/history.html:180,207-208` —
  `class=`/`value=`에 서버 이넘 값을 `esc()` 없이 보간. 백엔드 이넘 강제에 의존(현재 안전, defense-in-depth).
- **빌드 다운로드 무결성**: `build_allinone.py:44` — python.org 임베드 zip SHA256 미검증(TLS로 일부 완화).
  권고: 해시 핀.

---

## 6. 안전 확인됨 (검토 결과 문제 없음)

- **SQL 인젝션**: 전부 SQLAlchemy ORM/바인딩 파라미터. 유일한 raw SQL(`app/db.py:69-74`)은
  하드코딩 컬럼명만 사용. `ilike(f"%{q}%")`도 파라미터화됨.
- **업로드 경로 traversal**: `app/core/files.py` `safe_filename`이 `PurePosixPath(...).name` +
  화이트리스트로 적절히 차단. 저장 경로는 `{sha}_{safe_filename}` 형태.
- **파일 read/serve traversal**: 서빙 경로는 DB에 서버가 저장한 값 — 요청 path 파라미터로 조립하지 않음.
- **XXE / billion-laughs**: XML 파서 미사용(PDF=pypdf/pypdfium2, 피드=json/csv). openpyxl ≥3.1 하드닝.
- **언세이프 역직렬화**: pickle/yaml.load/eval/exec/marshal 없음. JSON/CSV/openpyxl만.
- **SSRF**: urllib/webhook URL은 관리자 환경설정 전용 — 요청별 사용자 URL이 `urlopen`에 도달하지 않음.
- **프론트 XSS**: React 본문 자동 이스케이프. board/history 의 `esc()` 는 `& < > " ' \``
  전부 이스케이프(작은따옴표·백틱 포함 — 인라인 JS 문자열 탈출 차단). 부서 행 선택은 인라인
  `onclick` 문자열 삽입 대신 `data-dept` 속성 + 위임 리스너로 처리해 데이터→코드 경로를 없앴다.
  app.dc.html 에 `dangerouslySetInnerHTML` 0건. href/src 는 고정 API 접두사 + 숫자 ID 로만 조립.
- **게시판 관리자 표식**: `is_admin` 은 공개·무인증 입력에서 받지 않는다(서버가 항상 False 로 저장).
  관리자 배지 스푸핑(클라이언트가 관리자로 위장한 공지 게시)을 차단.
- **라이브러리 버전**: React/ReactDOM 18.3.1, Babel 7.26.4 — 알려진 취약점 없음.
- **업로드 검증**: 권고문 업로드는 `%PDF` 매직바이트 검증.
- **스크립트 무결성**: PowerShell NVD 동기화는 SHA256 검증, 인자 리스트 subprocess(`shell=True` 없음).
  스케줄 작업 등록 기본은 **현재 사용자 권한(최소 권한)** 이며, 관리자 권한이 필요할 때만
  `-Elevated` 로 명시 opt-in(이 경우 스크립트 폴더 ACL 보호 권장).

---

## 7. 우선순위 요약

1. ~~**H-1, H-2, H-3, H-4, H-7**~~ — ✅ **조치 완료**(관리자 로그인 + 웹훅 HMAC + 증빙 하드닝).
2. **H-5, H-6** — **미조치**. 미신뢰 파일/리포트 처리(압축폭탄·수식 인젝션)로 이번 인증 작업 범위 밖이다.
   H-5(피드 압축폭탄)는 이제 관리자 인증이 필요해 공격 표면이 좁아졌으나, 해제 크기 상한은 여전히 없다.
   H-6(XLSX 수식 인젝션)은 리포트를 여는 검토자에게 그대로 남아 있다 — 후속 작업 필요.
3. **M-1, Low** — 하드닝. (M-2 CORS·M-3 CDN 폴백·M-4 설치 인터넷 의존은 조치 완료.)
   Low 중 `notifications` 의 원본 파일명 저장(헤더 인젝션 소지)은 이번에 함께 정정했다.

## 8. 잔여 위험 — 파일 접근통제의 한계 (2026-08 추가)

업로드물은 정적 서빙 경로 밖에 있고 API 인증을 통해서만 나가며, 디스크는 NTFS ACL
(상속 제거 + SYSTEM·Administrators·구동 계정)로 제한한다. 다만 **저장 시 암호화는 하지 않는다**.

- 운영자 계정으로 `start.bat` 을 실행하는 현재 구성에서 ACL 은 일반 사용자와 네트워크 공유
  접근을 차단하지만, **같은 PC 의 다른 로컬 관리자는 소유권 획득으로 열람 가능**하다.
- `data/advisory.db` 도 평문이다 — 백업본 반출 시 매체 쪽 보호가 필요하다.
- 강화하려면 (a) 전용 저권한 서비스 계정 구동 + ACL 축소, 또는 (b) EFS/앱단 암호화가 필요하다.

> 본 보고서는 검토 결과 기록이다. §3~§5 의 ✅ 표기는 후속 브랜치에서 실제 조치된 항목이다.
