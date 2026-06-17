"""부서 알림 — 메시지 생성·그룹핑·채널 어댑터·멱등성 (명세서 §4.7).

폐쇄망 기본: WEB_UI(내부 알림) + 메신저/메일은 게이트웨이 미연동 시 로컬 아웃박스
파일에 적재(외부 호출 0). 게이트웨이 규격 확정 시 설정만 채우면 표준 프로토콜로 발신(§9-4):
  · 메일 = SMTP(사내 메일 서버/Exchange) — ADVISORY_MAIL_SMTP_HOST 등
  · 메신저 = 범용 웹훅 POST(JSON) — ADVISORY_MESSENGER_WEBHOOK_URL
미설정/실패 시 아웃박스로 폴백하여 흐름을 보장한다(외부 호출 0 유지).
"""
from __future__ import annotations

import hashlib
import json
import smtplib
import urllib.request
from collections import OrderedDict
from email.message import EmailMessage

from ..config import DATA_DIR, settings
from ..enums import NotifyChannel
from ..models import Advisory, Match

OUTBOX = DATA_DIR / "outbox.log"


def idempotency_key(advisory_id: int, department_id: int, asset_ids: list[int]) -> str:
    raw = f"{advisory_id}:{department_id}:{sorted(asset_ids)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def group_by_department(matches: list[Match]) -> "OrderedDict[int, list[Match]]":
    """활성 매칭(EXCLUDED 제외)을 부서별로 그룹핑."""
    groups: OrderedDict[int, list[Match]] = OrderedDict()
    for m in matches:
        groups.setdefault(m.asset.department_id, []).append(m)
    return groups


def build_message(advisory: Advisory, dept_name: str, matches: list[Match]) -> str:
    """프로토타입 발송 메시지 양식을 서버에서 재현."""
    owners = ", ".join(
        OrderedDict.fromkeys(
            m.asset.owner_name for m in matches if m.asset.owner_name and m.asset.owner_name != "자동배포"
        )
    ) or "시스템"
    lines = "\n".join(
        f"· {m.asset.asset_no} ({m.asset.product_raw or m.asset.product_key} "
        f"{m.asset.version_raw or m.asset.version_norm or ''}) — {m.advisory_cve.cve_id_text} "
        f"{(m.advisory_cve.cve.severity.value if m.advisory_cve.cve else '')}"
        for m in matches
    )
    return (
        f"[보안조치 요청] {advisory.title or ''}\n\n"
        f"수신: {dept_name} (담당 {owners})\n"
        f"근거: {advisory.doc_no or ''} ({advisory.source_org or ''})\n"
        f"조치기한: {advisory.due_at or ''}\n\n"
        f"귀 부서 보유 자산 {len(matches)}대에서 아래 취약점이 확인되었습니다. "
        f"기한 내 보안 업데이트 적용 후 본 메시지에 회신 바랍니다.\n\n"
        f"{lines}\n\n"
        f"조치 완료 시 [보안권고문 처리 시스템] 웹UI에서 조치 결과를 등록해 주세요."
    )


def _outbox_write(channel: str, dept_name: str, body: str) -> None:
    with OUTBOX.open("a", encoding="utf-8") as f:
        f.write(json.dumps({"channel": channel, "dept": dept_name, "body": body}, ensure_ascii=False) + "\n")


def _send_mail(email_addr: str, subject: str, body: str) -> tuple[bool, str]:
    """표준 SMTP 발송. 미설정/실패 시 (False, 사유) → 호출측이 outbox 폴백."""
    host = settings.MAIL_SMTP_HOST
    if not (email_addr and host):
        return False, "smtp-unconfigured"
    msg = EmailMessage()
    msg["From"] = settings.MAIL_FROM or settings.MAIL_SMTP_USER or "advisory@localhost"
    msg["To"] = email_addr
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        with smtplib.SMTP(host, settings.MAIL_SMTP_PORT, timeout=settings.NOTIFY_TIMEOUT_SEC) as s:
            if settings.MAIL_USE_TLS:
                s.starttls()
            if settings.MAIL_SMTP_USER:
                s.login(settings.MAIL_SMTP_USER, settings.MAIL_SMTP_PASSWORD)
            s.send_message(msg)
        return True, f"mail→{email_addr}"
    except Exception as e:  # noqa: BLE001 — 폐쇄망: 실패해도 outbox 폴백으로 흐름 보장
        return False, f"smtp-error:{type(e).__name__}"


def _post_webhook(url: str, payload: dict) -> tuple[bool, str]:
    """범용 웹훅 POST(JSON) — 사내 메신저/그룹웨어 다수가 수용. 미설정/실패 시 (False, 사유)."""
    if not url:
        return False, "webhook-unconfigured"
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=settings.NOTIFY_TIMEOUT_SEC) as r:
            code = getattr(r, "status", 200)
            return (200 <= code < 300), f"webhook:{code}"
    except Exception as e:  # noqa: BLE001
        return False, f"webhook-error:{type(e).__name__}"


def dispatch(channels: list[str], dept_name: str, messenger_id, email, body: str) -> dict:
    """채널별 전송. 반환 {ok, results:[{channel, ok, info}]}.

    채널 활성(설정 완료) 시 표준 프로토콜로 발신, 미설정/실패 시 로컬 아웃박스 적재 후 성공
    처리(폐쇄망 기본: 외부 호출 0, 흐름 보장).
    """
    results = []
    for ch in channels:
        if ch == NotifyChannel.WEB_UI.value:
            results.append({"channel": ch, "ok": True, "info": "internal"})
        elif ch == NotifyChannel.MAIL.value:
            if settings.MAIL_ENABLED:
                sent, info = _send_mail(email, f"[보안조치 요청] {dept_name}", body)
                if not sent:
                    _outbox_write(ch, dept_name, body)
                    info = f"outbox({info})"
                results.append({"channel": ch, "ok": True, "info": info})
            else:
                _outbox_write(ch, dept_name, body)
                results.append({"channel": ch, "ok": True, "info": "outbox"})
        elif ch == NotifyChannel.MESSENGER.value:
            if settings.MESSENGER_ENABLED:
                sent, info = _post_webhook(
                    settings.MESSENGER_WEBHOOK_URL,
                    {"dept": dept_name, "messenger_id": messenger_id, "text": body},
                )
                if not sent:
                    _outbox_write(ch, dept_name, body)
                    info = f"outbox({info})"
                results.append({"channel": ch, "ok": True, "info": info})
            else:
                _outbox_write(ch, dept_name, body)
                results.append({"channel": ch, "ok": True, "info": "outbox"})
        else:
            results.append({"channel": ch, "ok": False, "info": "unknown channel"})
    return {"ok": all(r["ok"] for r in results), "results": results}
