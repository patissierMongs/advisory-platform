"""그룹웨어 게시판 연동 어댑터 (§★★★).

최초 프로세스(게시판에 권고문 게시 → 부서 댓글로 회신)를 시스템 ack 와 동기화한다.
실제 그룹웨어 API 규격(다우오피스/네이버웍스/자체 등)은 조직별로 다르므로 어댑터 뒤로 격리.
ADVISORY_GROUPWARE_WEBHOOK_URL 설정 시 범용 웹훅 POST 로 게시, 미설정/실패 시 로컬 아웃박스에
적재하고 post_id 를 반환(외부 호출 0, 흐름 검증 가능).
"""
from __future__ import annotations

import json
import urllib.request

from ..config import DATA_DIR, settings
from .. import enums

BOARD_OUTBOX = DATA_DIR / "groupware_board.log"


def post_board(advisory_id: int, doc_no: str, title: str, body: str) -> str:
    """게시판에 권고문 게시. 반환 post_id."""
    post_id = f"BOARD-{advisory_id}"
    url = getattr(settings, "GROUPWARE_WEBHOOK_URL", "")
    if getattr(settings, "GROUPWARE_ENABLED", False) and url:
        try:
            req = urllib.request.Request(
                url,
                data=json.dumps({"doc_no": doc_no, "title": title, "body": body}, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=getattr(settings, "NOTIFY_TIMEOUT_SEC", 10)) as r:
                data = json.loads((r.read().decode("utf-8") or "{}"))
                return str(data.get("post_id") or data.get("id") or post_id)
        except Exception:  # noqa: BLE001 — 실패 시 board.log 폴백
            pass
    with BOARD_OUTBOX.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"post_id": post_id, "doc_no": doc_no, "title": title, "body": body},
                           ensure_ascii=False) + "\n")
    return post_id


def parse_ack_webhook(payload: dict) -> dict | None:
    """게시판 댓글 회신 웹훅 → 표준 ack 형태로 정규화.

    기대 payload(예): {"department":"도로국","status":"DONE"|"IN_PROGRESS"|"UNABLE","note":"..","by":".."}
    그룹웨어별 필드명이 다르면 여기서 매핑한다.
    """
    dept = payload.get("department") or payload.get("dept")
    raw = (payload.get("status") or payload.get("ack") or "").upper()
    alias = {"완료": "DONE", "조치완료": "DONE", "진행중": "IN_PROGRESS", "불가": "UNABLE", "조치불가": "UNABLE"}
    status = alias.get(payload.get("status", ""), raw)
    if not dept or status not in enums.AckStatus.__members__:
        return None
    return {"department": dept, "ack_status": status, "note": payload.get("note"), "by": payload.get("by")}
