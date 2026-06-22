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

전 엔드포인트가 **무인증**이다. 폐쇄망(인트라넷) 전제의 의도된 설계이나, 그 위에서
삭제·발송·상태 위조·파일 업로드 등 민감 동작과 PII 노출이 무방비로 열려 있어 위험이 증폭된다.
아래 High 항목 다수는 이 무인증 구조 위에서 영향이 커진다.

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

### H-2. 무인증 댓글 삭제
- 위치: `app/routers/board.py:542` (`DELETE /comments/{id}`)
- 내용: 주석은 "관리자 화면에서만 호출"이라 명시하나 **실제 권한 검증이 전혀 없음**.
  네트워크상 누구나 임의 댓글(=공식 회신) 삭제 가능.
- 권고: 관리자 인증/토큰 게이트 추가.

### H-3. 무인증 임의 메일 발송
- 위치: `app/routers/notifications.py:160-162` (`POST /notify/test`)
- 내용: 임의 주소로 SMTP 메일 발송 가능. 메일 남용/스팸 중계 발판.
- 권고: 관리자 전용 게이트, 수신 도메인 제한.

### H-4. 서명 없는 그룹웨어 ack 웹훅
- 위치: `app/routers/remediation.py:137-160` (`POST /webhooks/groupware/ack`)
- 내용: 시크릿/서명 검증 없이 누구나 임의 부서의 **보안조치를 "완료(DONE)"로 위조** 가능.
  보안 조치현황 무결성 훼손.
- 권고: 공유 시크릿 또는 HMAC 서명 검증.

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

---

## 4. Medium

### M-1. openpyxl 메모리 DoS (자산 임포트)
- 위치: `app/core/assets_import.py:84-109` (`_load_sheet`)
- `read_only=False`로 전체 시트를 list-of-lists로 복사 + 병합범위 forward-fill, 행/셀 상한 없음.
  악성 `.xlsx`(거대 dimension/shared strings)로 OOM 가능. 관리자 대면이라 H보다 낮음.
- 권고: 최대 셀 수 가드, 업로드 크기 제한, 기존 `tests/test_assets_import_safety.py`의 oversized 케이스 커버 확인.

### M-2. CORS 와일드카드 기본값
- 위치: `app/main.py:89-94`
- `allow_origins=["*"]` + 모든 메서드/헤더. credentials 미허용이라 영향은 제한적이나
  내부 운영앱 기본값으로는 과도. 권고: 동일 출처 서빙 시 CORS 제거 또는 출처 한정.

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
- **프론트 XSS**: React 본문 자동 이스케이프, board/history는 `esc()`로 댓글 본문·작성자·부서명·자산 데이터 이스케이프.
  app.dc.html에 `dangerouslySetInnerHTML` 0건. href/src는 고정 API 접두사 + 숫자 ID로만 조립.
- **라이브러리 버전**: React/ReactDOM 18.3.1, Babel 7.26.4 — 알려진 취약점 없음.
- **업로드 검증**: 권고문 업로드는 `%PDF` 매직바이트 검증.
- **스크립트 무결성**: PowerShell NVD 동기화는 SHA256 검증, 인자 리스트 subprocess(`shell=True` 없음),
  스케줄 작업은 SYSTEM 아닌 현재 사용자 권한.

---

## 7. 우선순위 요약

1. **H-1, H-2, H-3, H-4, H-7** — 무인증 구조 위 민감 동작/노출. 관리자 게이트·서명·접근제어로 보완.
2. **H-5, H-6** — 미신뢰 파일/리포트 처리(압축폭탄·수식 인젝션). 입력·출력 정제.
3. **M-1~M-4, Low** — 하드닝. (M-3 CDN 폴백·M-4 설치 인터넷 의존은 본 브랜치에서 조치 완료.)

> 본 보고서는 검토 결과 기록이며, 코드 수정은 포함하지 않는다(요청에 따라 보고서만 작성).
