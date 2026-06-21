"""SMTP 기준 발송 상태 테스트."""
from __future__ import annotations

import pytest

from app import enums
from app.config import settings
from app.db import SessionLocal
from app.models import Advisory, AdvisoryCve, Asset, Cve, Department, Match, Notification


@pytest.fixture()
def notify_fixture():
    with SessionLocal() as db:
        dept = Department(name="SMTP테스트부서", email="smtp-test@example.go.kr", is_active=True)
        adv = Advisory(doc_no="SMTP-1", title="SMTP 테스트 권고문", status=enums.AdvisoryStatus.EXTRACTED)
        cve = Cve(cve_id="CVE-2098-1000", product_name="Google Chrome",
                  product_key="google_chrome", affected_versions="*",
                  severity=enums.Severity.HIGH)
        db.add_all([dept, adv, cve])
        db.commit()
        asset = Asset(asset_no="SMTP-ASSET-1", department_id=dept.id,
                      product_raw="Google Chrome", product_key="google_chrome",
                      version_raw="120", version_norm="120",
                      status=enums.AssetStatus.NORMAL)
        ac = AdvisoryCve(advisory_id=adv.id, cve_id_text=cve.cve_id, cve_ref_id=cve.id,
                         lookup_status=enums.LookupStatus.FOUND)
        db.add_all([asset, ac])
        db.commit()
        mt = Match(advisory_id=adv.id, advisory_cve_id=ac.id, asset_id=asset.id,
                   status=enums.MatchStatus.MATCHED)
        db.add(mt)
        db.commit()
        ids = {"advisory": adv.id, "department": dept.id}
    yield ids
    with SessionLocal() as db:
        from sqlalchemy import delete

        db.execute(delete(Notification).where(Notification.advisory_id == ids["advisory"]))
        db.execute(delete(Match).where(Match.advisory_id == ids["advisory"]))
        db.execute(delete(AdvisoryCve).where(AdvisoryCve.advisory_id == ids["advisory"]))
        db.execute(delete(Asset).where(Asset.asset_no == "SMTP-ASSET-1"))
        db.execute(delete(Advisory).where(Advisory.id == ids["advisory"]))
        db.execute(delete(Department).where(Department.id == ids["department"]))
        db.commit()


@pytest.fixture()
def restore_mail_settings():
    old = {
        "MAIL_ENABLED": settings.MAIL_ENABLED,
        "MAIL_SMTP_HOST": settings.MAIL_SMTP_HOST,
        "MAIL_FROM": settings.MAIL_FROM,
    }
    yield
    for k, v in old.items():
        setattr(settings, k, v)


def test_mail_disabled_marks_notification_failed(client, notify_fixture, restore_mail_settings):
    settings.MAIL_ENABLED = False
    settings.MAIL_SMTP_HOST = ""
    aid = notify_fixture["advisory"]

    r = client.post(f"/api/v1/advisories/{aid}/notifications",
                    json={"all": True, "channels": ["MAIL", "WEB_UI"]})

    assert r.status_code == 200, r.text
    row = r.json()["results"][0]
    assert row["status"] == "FAILED"
    assert any(d["channel"] == "MAIL" and d["ok"] is False for d in row["delivery_results"])
    assert any(d["channel"] == "WEB_UI" and d["ok"] is True for d in row["delivery_results"])
    with SessionLocal() as db:
        adv = db.get(Advisory, aid)
        n = db.get(Notification, row["notification_id"])
        assert adv.status == enums.AdvisoryStatus.NOTIFYING
        assert n.status == enums.NotificationStatus.FAILED


def test_default_notification_channels_fail_when_smtp_unconfigured(client, notify_fixture, restore_mail_settings):
    settings.MAIL_ENABLED = True
    settings.MAIL_SMTP_HOST = ""
    aid = notify_fixture["advisory"]

    r = client.post(f"/api/v1/advisories/{aid}/notifications", json={"all": True})

    assert r.status_code == 200, r.text
    row = r.json()["results"][0]
    assert row["status"] == "FAILED"
    assert any(d["channel"] == "MAIL" and d["ok"] is False and d["info"] == "smtp-unconfigured"
               for d in row["delivery_results"])
    assert any(d["channel"] == "WEB_UI" and d["ok"] is True for d in row["delivery_results"])
    with SessionLocal() as db:
        adv = db.get(Advisory, aid)
        n = db.get(Notification, row["notification_id"])
        assert adv.status == enums.AdvisoryStatus.NOTIFYING
        assert n.status == enums.NotificationStatus.FAILED


def test_smtp_success_marks_notification_sent(client, notify_fixture, restore_mail_settings, monkeypatch):
    settings.MAIL_ENABLED = True
    settings.MAIL_SMTP_HOST = "smtp.local"

    from app.core import notify

    monkeypatch.setattr(notify, "_send_mail", lambda email, subject, body: (True, f"mail->{email}"))
    aid = notify_fixture["advisory"]

    r = client.post(f"/api/v1/advisories/{aid}/notifications",
                    json={"all": True, "channels": ["MAIL", "WEB_UI"]})

    assert r.status_code == 200, r.text
    row = r.json()["results"][0]
    assert row["status"] == "SENT"
    assert any(d["channel"] == "MAIL" and d["ok"] is True for d in row["delivery_results"])
    with SessionLocal() as db:
        adv = db.get(Advisory, aid)
        n = db.get(Notification, row["notification_id"])
        assert adv.status == enums.AdvisoryStatus.COMPLETED
        assert n.status == enums.NotificationStatus.SENT


def test_notify_status_and_test_endpoint(client, restore_mail_settings, monkeypatch):
    settings.MAIL_ENABLED = True
    settings.MAIL_SMTP_HOST = "smtp.local"
    settings.MAIL_FROM = "advisory@example.go.kr"

    from app.core import notify

    monkeypatch.setattr(notify, "_send_mail", lambda email, subject, body: (True, "mail-ok"))
    status = client.get("/api/v1/notify/status").json()
    assert status["mail_enabled"] is True
    assert status["smtp_configured"] is True
    assert status["smtp_from"] == "advisory@example.go.kr"

    test = client.post("/api/v1/notify/test", json={"to": "target@example.go.kr"}).json()
    assert test == {"ok": True, "info": "mail-ok"}
