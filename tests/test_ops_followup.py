"""§개편 후속 — 피드→추출사전 동기화, 피드 실패 이력, 관리 인덱스 검색, 자동 재작업."""
from __future__ import annotations

import io
import json

import pytest
from sqlalchemy import delete, select

from app import enums
from app.core.normalize import PRODUCT_ALIASES, _build_index
from app.db import SessionLocal
from app.models import (
    Advisory, AdvisoryCve, AdvisoryIndex, AdvisoryProduct, CveFeedImport, Match,
)
from app.seed import _minimal_pdf


def _upload(client, lines, **data):
    pdf = _minimal_pdf(list(lines))
    r = client.post("/api/v1/advisories",
                    files={"file": (f"f-{abs(hash(tuple(lines)))}.pdf", io.BytesIO(pdf), "application/pdf")},
                    data=data)
    assert r.status_code == 201, r.text
    aid = r.json()["id"]
    with SessionLocal() as db:
        adv = db.get(Advisory, aid)
        adv.extracted_text = "\n".join(lines)   # _minimal_pdf 는 ASCII 전용 — 한글 본문 주입
        db.commit()
    return aid


@pytest.fixture()
def cleanup():
    ids: dict[str, list[int]] = {"advisory": []}
    yield ids
    with SessionLocal() as db:
        for aid in ids["advisory"]:
            db.execute(delete(Match).where(Match.advisory_id == aid))
            db.execute(delete(AdvisoryIndex).where(AdvisoryIndex.advisory_id == aid))
            db.execute(delete(AdvisoryProduct).where(AdvisoryProduct.advisory_id == aid))
            db.execute(delete(AdvisoryCve).where(AdvisoryCve.advisory_id == aid))
            db.execute(delete(Advisory).where(Advisory.id == aid))
        db.commit()


@pytest.fixture()
def _alias_rollback():
    """추출 사전 오염 방지 — 테스트가 추가한 별칭 원복(큐레이션 + 동적, 모듈 전역)."""
    import copy

    from app.core import normalize
    snapshot = copy.deepcopy(PRODUCT_ALIASES)
    dyn_snapshot = dict(normalize.DYNAMIC_ALIASES)
    yield
    PRODUCT_ALIASES.clear()
    PRODUCT_ALIASES.update(snapshot)
    normalize._ALIAS_INDEX = _build_index()
    normalize.DYNAMIC_ALIASES.clear()
    normalize.DYNAMIC_ALIASES.update(dyn_snapshot)
    normalize._rebuild_dynamic_index()


def _feed(client, records):
    payload = json.dumps({"cves": records}).encode()
    r = client.post("/api/v1/cve-feeds",
                    files={"file": ("f.json", io.BytesIO(payload), "application/json")})
    assert r.status_code == 200, r.text
    return r.json()["import_id"]


def test_feed_apply_syncs_extraction_dictionary(client, cleanup, _alias_rollback):
    """피드 적용 → CVE DB 제품명이 본문 추출 사전에 반영(§개편 후속 1)."""
    from app.core.product_extract import extract_products

    # 사전에 없는 제품 — 버전 인접 패턴 없이는 추출 불가한 문장.
    text = "Jenkins 취약점이 발견되었으며 서버 관리자는 주의 바람. 2.401 이하 버전이 영향."
    assert all(p["product_key"] != "jenkins" for p in extract_products(text))

    imp = _feed(client, [{"cve_id": "CVE-2099-9301", "product": "Jenkins",
                          "versions": "*", "severity": "HIGH"}])
    r = client.post(f"/api/v1/cve-feeds/{imp}/apply")
    assert r.status_code == 200
    assert r.json()["new_aliases"] >= 1

    hits = {p["product_key"]: p for p in extract_products(text)}
    assert "jenkins" in hits                       # 사전 등재 후 문맥 창 추출 성공
    assert hits["jenkins"]["affected_versions"] == {"lte": "2.401"}


def test_feed_apply_failure_marks_history_failed(client):
    """적용 실패가 이력에 성공처럼 남지 않음(§개편 후속 3) — FAILED + 사유."""
    imp = _feed(client, [{"cve_id": "CVE-2099-9302", "product": "nginx", "severity": "HIGH"}])
    with SessionLocal() as db:
        row = db.get(CveFeedImport, imp)
        # 검증 후 파일 훼손: JSON 프레이밍은 유지하되 원소가 깨진 상태 → 파싱 예외 유발
        open(row.file_path, "wb").write(b'{"cves": [ not-valid-json')
        db.commit()
    r = client.post(f"/api/v1/cve-feeds/{imp}/apply")
    assert r.status_code == 500
    hist = client.get("/api/v1/cve-feeds").json()["items"]
    mine = next(i for i in hist if i["id"] == imp)
    assert mine["status"] == "FAILED"
    assert mine["error_message"]


def test_advisory_index_search_and_products_in_list(client, cleanup):
    """문서번호 중심 관리 인덱스(§개편 후속 6) — CVE 없어도 문서번호·제품으로 검색."""
    aid = _upload(client, ["Tomcat vuln"], doc_no="국토부-특별-2026-777", source_org="국토부")
    cleanup["advisory"].append(aid)
    client.post(f"/api/v1/advisories/{aid}/products",
                json={"product_name": "Apache Tomcat", "affected_versions": {"lte": "9.0.30"}})

    # 문서번호 검색
    r = client.get("/api/v1/advisories?q=특별-2026-777").json()
    assert any(i["id"] == aid for i in r["items"])
    # 제품명 검색 (CVE 0건이어도 히트)
    r = client.get("/api/v1/advisories?q=tomcat").json()
    hit = next(i for i in r["items"] if i["id"] == aid)
    assert any(p["key"] == "apache_tomcat" for p in hit["products"])
    assert "9.0.30" in " ".join(p["versions"] for p in hit["products"])
    # 미일치어
    r = client.get("/api/v1/advisories?q=존재하지않는검색어zz").json()
    assert all(i["id"] != aid for i in r["items"])


def test_reindex_excludes_hard_deleted_products(client, cleanup):
    """재추출로 delete 된 옛 제안이 인덱스에 섞이지 않음(stale 컬렉션 회귀)."""
    from app.core.advisory_ops import refresh_extracted_products, reindex_advisory

    aid = _upload(client, ["placeholder"], source_org="색인테스트")
    cleanup["advisory"].append(aid)
    with SessionLocal() as db:
        adv = db.get(Advisory, aid)
        db.add(AdvisoryProduct(advisory=adv, product_name="OldProd", product_key="oldprod",
                               affected_versions={"lte": "1.0"},
                               status="SUGGESTED", origin="EXTRACTED"))
        db.flush()
        _ = adv.products                      # 컬렉션 로드(운영 코드 경로 재현)
        refresh_extracted_products(db, adv, "Apache Tomcat 9.0.30 이하 버전 취약",
                                   revive_deleted=False)
        row = reindex_advisory(db, adv)
        keys = [p["key"] for p in row.products]
        assert "oldprod" not in keys          # delete 된 행이 색인에 남으면 실패
        assert "apache_tomcat" in keys
        db.rollback()


def test_versions_text_defensive_on_malformed_rules():
    """임의 object 규칙(range 형태 오류)에도 색인이 죽지 않음."""
    from app.core.advisory_ops import _versions_text

    assert _versions_text({"range": ["9.0", "9.5"]}) == "9.0~9.5"
    assert _versions_text({"range": ["9.0"]}) == "['9.0']"     # 크래시 없이 문자열화
    assert _versions_text({"range": None}) == "{'range': None}"
    assert _versions_text({"lte": "3.2"}) == "3.2이하"


def test_alias_ok_allows_two_char_korean(_alias_rollback):
    """한글 2음절 제품명('알약' 류)은 동적 사전 등재 허용, 라틴 2자는 계속 배제."""
    from app.core import normalize

    n = normalize.sync_aliases_from_cves([("알약", "estsoft_alyac"), ("go", "golang")])
    assert n == 1
    assert normalize.DYNAMIC_ALIASES.get("알약") == "estsoft_alyac"
    assert "go" not in normalize.DYNAMIC_ALIASES


def test_dynamic_aliases_do_not_touch_asset_normalization(_alias_rollback):
    """피드 유래 별칭이 자산 정규화(normalize_product)를 바꾸지 않음(§적대검증 확정).

    NVD 제품명('microsoft windows')이 최장일치로 큐레이션 별칭('windows server')을
    가리면 자산 키 산출이 피드 적용 여부에 따라 달라져 기존 매칭이 깨진다.
    """
    from app.core import normalize

    before = normalize.normalize_product("Microsoft Windows Server 2019")
    normalize.sync_aliases_from_cves([("Microsoft Windows", "microsoft_windows")])
    assert normalize.normalize_product("Microsoft Windows Server 2019") == before
    # 동적 사전에는 들어가서 본문 추출(버전 문맥 有)에는 쓰인다.
    assert normalize.DYNAMIC_ALIASES.get("microsoft windows") == "microsoft_windows"


def test_dynamic_alias_requires_version_context(_alias_rollback):
    """동적 별칭은 버전 문맥 없으면 제안하지 않음 — '*' 잡음 억제(§적대검증 확정)."""
    from app.core import normalize
    from app.core.product_extract import extract_products

    normalize.sync_aliases_from_cves([("NoisyProduct", "noisyproduct")])
    # 버전 문맥 없음 → 제안 없음
    assert all(p["product_key"] != "noisyproduct"
               for p in extract_products("NoisyProduct 관련 일반 공지입니다."))
    # 버전 문맥 있음 → 규칙과 함께 제안
    hits = {p["product_key"]: p for p in extract_products("NoisyProduct 2.5 이하 버전 취약점")}
    assert hits["noisyproduct"]["affected_versions"] == {"lte": "2.5"}


def test_feed_apply_post_step_failure_stays_applied(client, monkeypatch, _alias_rollback):
    """CVE 반영 후 후처리(재작업) 실패 → 500 아님, APPLIED + 경고 메시지(정직한 이력)."""
    from app.routers import cve_feeds as feeds_router

    def _boom(db):
        raise RuntimeError("rework exploded")

    monkeypatch.setattr(feeds_router.advisory_ops, "rework_open_advisories", _boom)
    imp = _feed(client, [{"cve_id": "CVE-2099-9304", "product": "PostFailProd",
                          "severity": "LOW"}])
    r = client.post(f"/api/v1/cve-feeds/{imp}/apply")
    assert r.status_code == 200
    assert r.json()["added_count"] >= 1
    assert "rework exploded" in (r.json()["post_error"] or "")
    hist = client.get("/api/v1/cve-feeds").json()["items"]
    mine = next(i for i in hist if i["id"] == imp)
    assert mine["status"] == "APPLIED"        # CVE 는 실제 반영됨
    assert "후처리 실패" in (mine["error_message"] or "")
    with SessionLocal() as db:
        from app.models import Cve
        db.execute(delete(Cve).where(Cve.cve_id == "CVE-2099-9304"))
        db.commit()


def test_feed_correction_retracts_stale_matches(client, cleanup, _alias_rollback):
    """정정 피드로 성립하지 않게 된 매칭 회수 — 미회신만 삭제, 회신 이력은 stale 보존."""
    from app.models import Asset, Department

    with SessionLocal() as db:
        dept = Department(name="회수테스트부", code="RTRCT")
        db.add(dept); db.flush()
        a1 = Asset(asset_no="RT-1", department_id=dept.id, product_key="retractprod",
                   product_raw="RetractProd", version_raw="3.0", version_norm="3.0")
        a2 = Asset(asset_no="RT-2", department_id=dept.id, product_key="retractprod",
                   product_raw="RetractProd", version_raw="3.0", version_norm="3.0")
        db.add_all([a1, a2]); db.commit()
        dept_id, a1_id, a2_id = dept.id, a1.id, a2.id

    aid = _upload(client, ["RetractProd advisory CVE-2099-9305"], source_org="회수")
    cleanup["advisory"].append(aid)
    client.post(f"/api/v1/advisories/{aid}/cves", json={"cve_id": "CVE-2099-9305"})
    imp = _feed(client, [{"cve_id": "CVE-2099-9305", "product": "RetractProd",
                          "versions": "*", "severity": "HIGH"}])
    assert client.post(f"/api/v1/cve-feeds/{imp}/apply").status_code == 200
    r = client.post(f"/api/v1/advisories/{aid}/match")
    assert r.status_code == 200 and r.json()["matched"] == 2

    with SessionLocal() as db:   # 한 자산은 조치 완료 회신 상태로
        m2 = db.scalar(select(Match).where(
            Match.advisory_id == aid, Match.asset_id == a2_id))
        m2.ack_status = enums.AckStatus.DONE
        db.commit()

    # 정정 피드: 3.0 은 영향 아님(열거에서 제외) → 재작업이 미회신 매칭만 회수
    imp2 = _feed(client, [{"cve_id": "CVE-2099-9305", "product": "RetractProd",
                           "versions": "1.0;2.0", "severity": "HIGH"}])
    assert client.post(f"/api/v1/cve-feeds/{imp2}/apply").status_code == 200
    with SessionLocal() as db:
        rows = db.scalars(select(Match).where(Match.advisory_id == aid)).all()
        by_asset = {m.asset_id: m for m in rows}
        assert a1_id not in by_asset                     # 미회신 → 삭제
        assert a2_id in by_asset                         # 회신 이력 → 보존
        assert (by_asset[a2_id].match_reason or {}).get("stale") is True
        # 정리
        db.execute(delete(Match).where(Match.advisory_id == aid))
        from app.models import Cve
        db.execute(delete(AdvisoryCve).where(AdvisoryCve.cve_id_text == "CVE-2099-9305"))
        db.execute(delete(Cve).where(Cve.cve_id == "CVE-2099-9305"))
        db.execute(delete(Asset).where(Asset.id.in_([a1_id, a2_id])))
        db.execute(delete(Department).where(Department.id == dept_id))
        db.commit()


def test_feed_apply_reworks_open_advisories(client, cleanup, _alias_rollback):
    """피드 적용 시 미완료 권고문 자동 재추출·재색인(§개편 후속 7)."""
    aid = _upload(client, ["GlobalWidget 3.2 이하 버전 취약점", "CVE-2099-9303 참조"],
                  source_org="재작업테스트")
    cleanup["advisory"].append(aid)
    # NOT_FOUND CVE 수동 등록 → NEEDS_CVE_UPDATE 게이트 상태
    client.post(f"/api/v1/advisories/{aid}/cves", json={"cve_id": "CVE-2099-9303"})
    assert client.get(f"/api/v1/advisories/{aid}").json()["status"] == "NEEDS_CVE_UPDATE"

    imp = _feed(client, [{"cve_id": "CVE-2099-9303", "product": "GlobalWidget",
                          "versions": "3.0;3.1;3.2", "severity": "HIGH"}])
    r = client.post(f"/api/v1/cve-feeds/{imp}/apply").json()
    assert r["advisories_unlocked"] >= 1
    assert r["reworked"] >= 1

    # 게이트 해제 + 재추출로 제품 제안 생성 + 인덱스에 CVE·제품 반영
    assert client.get(f"/api/v1/advisories/{aid}").json()["status"] == "EXTRACTED"
    prods = client.get(f"/api/v1/advisories/{aid}/products").json()["items"]
    assert any(p["product_key"] == "globalwidget" and p["affected_versions"] == {"lte": "3.2"}
               for p in prods)
    hit = client.get("/api/v1/advisories?q=globalwidget").json()["items"]
    row = next(i for i in hit if i["id"] == aid)
    assert "CVE-2099-9303" in row["cves"]
    with SessionLocal() as db:
        db.execute(delete(AdvisoryIndex).where(AdvisoryIndex.advisory_id == aid))
        from app.models import Cve
        for code in ("CVE-2099-9301", "CVE-2099-9302", "CVE-2099-9303"):
            db.execute(delete(AdvisoryCve).where(AdvisoryCve.cve_id_text == code))
            db.execute(delete(Cve).where(Cve.cve_id == code))
        db.commit()
