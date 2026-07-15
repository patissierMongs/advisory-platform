"""출처 자동 탐지(§출처) — 우선순위(상위 폴더명→폴더명→파일명→본문)·일괄/개별 지정."""
from __future__ import annotations

import io

from app.seed import _minimal_pdf


def _upload(client, name, lines, rel_path=None, **form):
    pdf = _minimal_pdf(lines)
    data = dict(form)
    if rel_path is not None:
        data["rel_path"] = rel_path
    r = client.post(
        "/api/v1/advisories",
        files={"file": (name, io.BytesIO(pdf), "application/pdf")},
        data=data,
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_detect_from_filename(client):
    body = _upload(client, "KISA-2099-0001.pdf", ["advisory body", "CVE-2099-2000"])
    assert body["source_org"] == "KISA"
    assert body["source_origin"] == "FILENAME"
    assert any(c["name"] == "KISA" and c["origin"] == "FILENAME"
               for c in body["source_candidates"])


def test_priority_parent_folder_over_filename_and_content(client):
    """상위 폴더명(NCSC) > 폴더명(KISA) > 파일명(CISA) — 최우선 후보가 자동 지정된다."""
    body = _upload(
        client, "CISA-notice-2099.pdf",
        ["NCTI shared advisory", "CVE-2099-2001"],
        rel_path="NCSC/KISA/CISA-notice-2099.pdf",
    )
    assert body["source_org"] == "NCSC"
    assert body["source_origin"] == "PARENT_FOLDER"
    names = [c["name"] for c in body["source_candidates"]]
    # 우선순위 순서대로 나열: 상위폴더 → 폴더 → 파일명 → 본문
    assert names == ["NCSC", "KISA", "CISA", "NCTI"]
    origins = {c["name"]: c["origin"] for c in body["source_candidates"]}
    assert origins == {"NCSC": "PARENT_FOLDER", "KISA": "FOLDER",
                       "CISA": "FILENAME", "NCTI": "CONTENT"}


def test_detect_from_content_alias_maps_to_canonical(client):
    """본문의 별칭(한국인터넷진흥원)이 대표 기관명(KISA)으로 정규화된다."""
    # _minimal_pdf 는 ASCII 만 렌더하므로 별칭도 ASCII 별칭(KrCERT)으로 검증.
    body = _upload(client, "adv-2099-b.pdf", ["Published by KrCERT team", "CVE-2099-2002"])
    assert body["source_org"] == "KISA"
    assert body["source_origin"] == "CONTENT"


def test_manual_source_wins_over_detection(client):
    body = _upload(client, "KISA-2099-0002.pdf", ["CVE-2099-2003"], source_org="운영기관")
    assert body["source_org"] == "운영기관"
    assert body["source_origin"] == "MANUAL"
    # 탐지 후보는 그래도 보존 — 이후 재지정에 사용.
    assert any(c["name"] == "KISA" for c in body["source_candidates"])


def test_short_ascii_alias_needs_word_boundary(client):
    """짧은 영문 별칭(NIS)은 단어 경계 없이는 오탐하지 않는다(administrator 등)."""
    body = _upload(client, "administrator-guide.pdf", ["furnish punish", "CVE-2099-2004"])
    assert body["source_org"] == "-"


def test_source_batch_apply_multiple(client):
    a = _upload(client, "batch-a-2099.pdf", ["CVE-2099-2005"])
    b = _upload(client, "batch-b-2099.pdf", ["CVE-2099-2006"])
    r = client.patch("/api/v1/advisories/source-batch",
                     json={"ids": [a["id"], b["id"]], "sources": ["국가정보원", "KISA"]})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["applied"] == 2
    assert out["source_org"] == "국가정보원, KISA"   # 복수 선택 = 복수 출처 기록
    for item in out["items"]:
        assert item["source_org"] == "국가정보원, KISA"
        assert item["source_origin"] == "MANUAL"


def test_meta_patch_source_individual_and_reset(client):
    a = _upload(client, "meta-src-2099.pdf", ["CVE-2099-2007"])
    r = client.patch(f"/api/v1/advisories/{a['id']}/meta", json={"source_org": "금융보안원"})
    assert r.status_code == 200
    assert r.json()["source_org"] == "금융보안원"
    assert r.json()["source_origin"] == "MANUAL"
    # 비우면 '-' 로 — 출처는 항상 값을 가진다.
    r = client.patch(f"/api/v1/advisories/{a['id']}/meta", json={"source_org": ""})
    assert r.json()["source_org"] == "-"
    assert r.json()["source_origin"] is None


def test_source_org_filter_matches_multi_source(client):
    a = _upload(client, "filter-src-2099.pdf", ["CVE-2099-2008"])
    client.patch("/api/v1/advisories/source-batch",
                 json={"ids": [a["id"]], "sources": ["국가정보원", "NCSC"]})
    r = client.get("/api/v1/advisories", params={"source_org": "NCSC"})
    assert any(item["id"] == a["id"] for item in r.json()["items"])
