#!/usr/bin/env python3
"""게시판 데모 시나리오 구성기 — 실행 중인 서버에 '테스트 가능한 게시판 상태'를 한 번에 만든다.

자산대장 엣지케이스 샘플과 맞물려 게시판을 실제로 눌러볼 수 있게, 다음을 API 로 수행한다
(stdlib 만 사용 — 폐쇄망에서 서버만 떠 있으면 어디서든 실행 가능):

  1. samples/demo_advisories/ 권고문 PDF 8건 업로드(폴더 상대경로 → 출처 자동 탐지) + CVE 추출
  2. samples/cve_feed_extended_2026-07.json 반입·적용 → 게이트 일괄 해제
  3. samples/자산관리대장_엣지케이스_샘플.xlsx 가져오기(자동 헤더 감지·추천 매핑)
  4. 각 권고문 자산 매칭 실행 → 내부 게시판 게시
  5. 대표 권고문에 부서 회신 댓글 시드: 조치완료(+증빙 첨부)·진행중·조치불가(사유)·일반 질의

사용:  python scripts/run_board_demo.py [--base http://localhost:8000]
멱등:  중복 PDF(409)는 건너뛰고, 자산은 upsert, 게시·댓글은 다시 추가된다(댓글만 누적됨).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "samples" / "demo_advisories"
FEED = ROOT / "samples" / "cve_feed_extended_2026-07.json"
XLSX = ROOT / "samples" / "자산관리대장_엣지케이스_샘플.xlsx"


def log(m: str) -> None:
    print(f"[board-demo] {m}", flush=True)


class Api:
    def __init__(self, base: str):
        self.base = base.rstrip("/") + "/api/v1"

    def json(self, method: str, path: str, payload=None):
        req = urllib.request.Request(
            self.base + path, method=method,
            data=json.dumps(payload).encode() if payload is not None else None,
            headers={"Content-Type": "application/json"} if payload is not None else {})
        with urllib.request.urlopen(req) as r:
            return json.load(r)

    def upload(self, path: str, filepath: Path, fields: dict | None = None,
               ctype: str = "application/octet-stream", filename: str | None = None):
        b = uuid.uuid4().hex
        body = b""
        for k, v in (fields or {}).items():
            body += (f"--{b}\r\nContent-Disposition: form-data; name=\"{k}\"\r\n\r\n{v}\r\n").encode()
        name = filename or filepath.name
        body += (f"--{b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{name}\"\r\n"
                 f"Content-Type: {ctype}\r\n\r\n").encode() + filepath.read_bytes() + (f"\r\n--{b}--\r\n").encode()
        req = urllib.request.Request(self.base + path, data=body,
                                     headers={"Content-Type": f"multipart/form-data; boundary={b}"})
        with urllib.request.urlopen(req) as r:
            return json.load(r)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base", default="http://localhost:8000", help="서버 주소(기본 localhost:8000)")
    args = ap.parse_args()
    api = Api(args.base)

    for p, what in ((DEMO, "권고문 샘플 폴더"), (FEED, "확장 CVE 피드"), (XLSX, "자산대장 샘플")):
        if not p.exists():
            sys.exit(f"{what} 없음: {p} — 먼저 python scripts/make_demo_samples.py 를 실행하세요.")

    # ① 권고문 업로드(폴더 상대경로 → 출처 자동 탐지) + 추출
    ids: list[int] = []
    dup = 0
    for pdf in sorted(DEMO.rglob("*.pdf")):
        rel = pdf.relative_to(DEMO).as_posix()
        try:
            adv = api.upload("/advisories", pdf, {"rel_path": rel}, "application/pdf")
        except urllib.error.HTTPError as e:
            if e.code == 409:
                dup += 1
                continue
            raise
        ids.append(adv["id"])
        api.json("POST", f"/advisories/{adv['id']}/extract", {})
        log(f"업로드 {rel} → 출처 {adv['source_org']} [{adv.get('source_origin')}]")
    if dup:
        log(f"중복(이미 등록) {dup}건 건너뜀")
    if ids:
        time.sleep(3)  # 백그라운드 추출 대기

    # ② 확장 피드 적용 → 게이트 해제
    imp = api.upload("/cve-feeds", FEED, ctype="application/json")
    r = api.json("POST", f"/cve-feeds/{imp['import_id']}/apply", {})
    log(f"CVE 피드 적용: 신규 {r['added_count']} · 갱신 {r['updated_count']} · 게이트 해제 {r['advisories_unlocked']}건")

    # ③ 자산대장 가져오기(자동 헤더 감지 + 추천 매핑)
    pv = api.upload("/assets/import/preview", XLSX)
    r = api.json("POST", f"/assets/import/{pv['import_id']}/commit", {
        "mapping": pv["suggested_mapping"], "header_row": pv["header_row"],
        "header_rows": pv.get("header_rows", 1), "mode": "append", "on_warning": "skip"})
    log(f"자산대장: {r['committed']}행 적재 · 경고 {len(r['warnings'])}건 · 부서 생성 {len(r['created_departments'])}개")

    # ④ 매칭 + 발송(WEB_UI 채널 — SMTP 불필요) + 게시판 게시 (재실행 안전)
    advs = api.json("GET", "/advisories?size=100")["items"]
    published = 0
    notified = 0
    for a in advs:
        try:
            api.json("POST", f"/advisories/{a['id']}/match", {})
        except urllib.error.HTTPError:
            pass  # 게이트 미충족(스캔본 등)은 매칭 없이 게시만
        try:
            # 발송 이력·조치 회신 데모를 위해 내부 기록 채널로 발송(멱등 — 재실행 시 무해).
            r = api.json("POST", f"/advisories/{a['id']}/notifications",
                         {"all": True, "channels": ["WEB_UI"]})
            notified += len(r.get("results") or [])
        except urllib.error.HTTPError:
            pass  # 매칭 자산 없는 권고문은 발송 대상 없음
        if not a.get("board_published"):
            api.json("POST", f"/advisories/{a['id']}/board", {})
            published += 1
    log(f"게시판 게시: {published}건 · 발송(WEB_UI): {notified}개 부서 (총 {len(advs)}건)")

    # ⑤ 대표 권고문(매칭 '부서'가 가장 많은 것)에 부서 회신 댓글 시드 — 회신 상태 다양성 확보
    depts = {d["name"]: d["id"] for d in api.json("GET", "/departments")["items"]}
    target = None
    best = 0
    for a2 in advs:
        mt = api.json("GET", f"/advisories/{a2['id']}/matches")["items"]
        n_depts = len({m["department"] for m in mt})
        if n_depts > best:
            best, target = n_depts, (a2, mt)
    if target is None:
        log("매칭된 권고문이 없어 댓글 시드는 건너뜀")
        return 0
    a, matches = target
    aid = a["id"]

    def comment(name, dept, body, ack=None, match_ids=None):
        payload = {"author_name": name, "body": body, "ack_status": ack}
        if dept in depts:
            payload["department_id"] = depts[dept]
        else:
            payload["department_name"] = dept
        if match_ids:
            payload["match_ids"] = match_ids
        return api.json("POST", f"/board/advisories/{aid}/comments", payload)

    by_dept: dict[str, list] = {}
    for m in matches:
        by_dept.setdefault(m["department"], []).append(m)

    dept_names = list(by_dept)
    made = 0
    if dept_names:
        d0 = dept_names[0]
        c = comment(next(x["owner_name"] or "담당자" for x in by_dept[d0]), d0,
                    "월례 패치(KB 누적 업데이트) 적용 완료했습니다. 재부팅까지 확인했습니다.",
                    ack="DONE", match_ids=[x["id"] for x in by_dept[d0]])
        # 증빙 첨부 — 조치 결과 텍스트 리포트(안전 타입, 게시판 팝업에서 inline 열람)
        ev = ROOT / "samples" / "demo_advisories" / "READ ME — 데모 사용법.txt"
        api.upload(f"/board/comments/{c['comment']['id']}/evidence", ev,
                   filename="patch_result_report.txt", ctype="text/plain")
        made += 1
    if len(dept_names) > 1:
        d1 = dept_names[1]
        comment(next(x["owner_name"] or "담당자" for x in by_dept[d1]), d1,
                "대상 장비 확인했습니다. 업무 영향 검토 후 이번 주 내 적용 예정입니다.", ack="IN_PROGRESS")
        made += 1
    if len(dept_names) > 2:
        d2 = dept_names[2]
        comment(next(x["owner_name"] or "담당자" for x in by_dept[d2]), d2,
                "해당 시스템은 공급사 검증 전이라 즉시 패치가 불가합니다. 임시 완화책(서비스 차단) 적용했습니다.",
                ack="UNABLE")
        made += 1
    comment("박문의", dept_names[0] if dept_names else "정보보호팀",
            "폐쇄망 PC 도 이번 권고문 대상에 포함되나요? 오프라인 패치 파일 위치 공유 부탁드립니다.")
    made += 1
    log(f"댓글 시드: '{a['title']}' 에 {made}건(조치완료+증빙 / 진행중 / 조치불가 / 일반 질의)")
    log(f"완료 — 게시판: {args.base}/board")
    return 0


if __name__ == "__main__":
    sys.exit(main())
