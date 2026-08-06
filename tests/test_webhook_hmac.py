"""그룹웨어 ack 웹훅 HMAC 서명 검증 (보안검토 H-4 회귀).

조치 전에는 시크릿·서명 없이 누구나 임의 부서의 보안 조치를 '완료'로 위조할 수 있었다.
여기서는 '거부됐다'만이 아니라 '조치 상태가 실제로 안 바뀌었다'까지 확인한다.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time

import pytest
from conftest import signed_webhook_post

from app import enums
from app.db import SessionLocal
from app.models import Advisory, Department, Notification

PATH = "/api/v1/webhooks/groupware/ack"


@pytest.fixture()
def pending_notification():
    """미종료 발송 1건 — 위조 성공 여부를 상태로 확인하기 위한 대상."""
    with SessionLocal() as db:
        dept = Department(name="웹훅검증부", is_active=True)
        db.add(dept)
        adv = Advisory(title="웹훅 검증 권고문", status=enums.AdvisoryStatus.NOTIFYING)
        db.add(adv)
        db.flush()
        n = Notification(advisory_id=adv.id, department_id=dept.id, channels=["WEB_UI"],
                         message_body="m", asset_ids=[],
                         status=enums.NotificationStatus.SENT,
                         ack_status=enums.AckStatus.NONE)
        db.add(n)
        db.commit()
        ids = (n.id, dept.name, adv.id)
    yield ids
    with SessionLocal() as db:
        db.query(Notification).filter(Notification.id == ids[0]).delete()
        db.query(Advisory).filter(Advisory.id == ids[2]).delete()
        db.query(Department).filter(Department.name == ids[1]).delete()
        db.commit()


def _ack_status(notification_id: int) -> str:
    with SessionLocal() as db:
        return db.get(Notification, notification_id).ack_status.value


def _raw_post(client, payload: dict, *, ts: str | None = None, sig: str | None = None):
    body = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if ts is not None:
        headers["X-Advisory-Timestamp"] = ts
    if sig is not None:
        headers["X-Advisory-Signature"] = sig
    return client.post(PATH, content=body, headers=headers)


def test_valid_signature_accepted(public_client, pending_notification):
    nid, dept_name, _ = pending_notification
    r = signed_webhook_post(public_client, PATH, {"department": dept_name, "status": "DONE"})
    assert r.status_code == 200, r.text
    assert _ack_status(nid) == "DONE"


def test_unsigned_rejected_and_state_unchanged(public_client, pending_notification):
    """무서명 위조 시도 — 401 이면서 조치 상태가 그대로여야 한다."""
    nid, dept_name, _ = pending_notification
    r = public_client.post(PATH, json={"department": dept_name, "status": "DONE"})
    assert r.status_code == 401, r.text
    assert r.json()["detail"]["code"] == "BAD_SIGNATURE"
    assert _ack_status(nid) == "NONE"


def test_bad_signature_rejected(public_client, pending_notification):
    nid, dept_name, _ = pending_notification
    r = _raw_post(public_client, {"department": dept_name, "status": "DONE"},
                  ts=str(int(time.time())), sig="sha256=" + "0" * 64)
    assert r.status_code == 401
    assert _ack_status(nid) == "NONE"


def test_tampered_body_rejected(public_client, pending_notification):
    """서명은 유효하지만 본문이 바뀐 경우 — 서명이 본문 전체를 덮는지 확인."""
    nid, dept_name, _ = pending_notification
    signed_body = json.dumps({"department": dept_name, "status": "IN_PROGRESS"}).encode()
    ts = str(int(time.time()))
    sig = hmac.new(os.environ["ADVISORY_WEBHOOK_SECRET"].encode(),
                   f"{ts}.".encode() + signed_body, hashlib.sha256).hexdigest()
    tampered = json.dumps({"department": dept_name, "status": "DONE"}).encode()
    r = public_client.post(PATH, content=tampered, headers={
        "Content-Type": "application/json",
        "X-Advisory-Timestamp": ts,
        "X-Advisory-Signature": f"sha256={sig}",
    })
    assert r.status_code == 401
    assert _ack_status(nid) == "NONE"


def test_stale_timestamp_rejected(public_client, pending_notification):
    """리플레이 창 밖 — 서명 자체는 올바르지만 타임스탬프가 오래됐다."""
    nid, dept_name, _ = pending_notification
    body = json.dumps({"department": dept_name, "status": "DONE"}).encode()
    ts = str(int(time.time()) - 400)
    sig = hmac.new(os.environ["ADVISORY_WEBHOOK_SECRET"].encode(),
                   f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    r = public_client.post(PATH, content=body, headers={
        "Content-Type": "application/json",
        "X-Advisory-Timestamp": ts,
        "X-Advisory-Signature": f"sha256={sig}",
    })
    assert r.status_code == 401
    assert _ack_status(nid) == "NONE"


def test_disabled_when_secret_unset(public_client, pending_notification, monkeypatch):
    """시크릿 미설정은 '무인증 허용'이 아니라 503(fail closed)이어야 한다."""
    from app.config import settings

    nid, dept_name, _ = pending_notification
    monkeypatch.setattr(settings, "WEBHOOK_SECRET", "")
    r = signed_webhook_post(public_client, PATH, {"department": dept_name, "status": "DONE"})
    assert r.status_code == 503
    assert r.json()["detail"]["code"] == "WEBHOOK_DISABLED"
    assert _ack_status(nid) == "NONE"
