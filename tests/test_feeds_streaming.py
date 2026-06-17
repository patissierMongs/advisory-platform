"""스트리밍 파서 회귀 테스트.

핵심: 스트리밍 결과가 배치 parse_feed 와 byte-identical 이어야 한다(조용한 CVE 누락 방지).
청크 크기를 극단적으로 줄여 모든 경계(이스케이프·중괄호·유니코드 한가운데)를 강제한다.
"""
from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from app.core import feeds


def _nvd(n: int, *, tricky: bool = False) -> dict:
    vulns = []
    for i in range(n):
        desc = (f'edge }} ] , "q\\" \\\\ 한글 {i} [n {{x}}]' if tricky else f"desc {i}")
        vulns.append({"cve": {
            "id": f"CVE-2099-{i:05d}",
            "published": "2099-03-04T12:00:00",
            "descriptions": [{"lang": "en", "value": desc}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}]},
            "configurations": [{"nodes": [{"cpeMatch": [
                {"vulnerable": True, "criteria": "cpe:2.3:a:v:p:1.0:*:*:*:*:*:*:*",
                 "versionEndExcluding": "2.0"}]}]}],
        }})
    return {"format": "NVD_CVE", "version": "2.0", "vulnerabilities": vulns}


def _write(p: Path, obj) -> str:
    p.write_text(json.dumps(obj, ensure_ascii=False), encoding="utf-8")
    return str(p)


@pytest.mark.parametrize("chunk", [13, 17, 64, 4096, 1 << 18])
def test_nvd_stream_matches_batch(tmp_path, monkeypatch, chunk):
    monkeypatch.setattr(feeds, "_STREAM_CHUNK", chunk)
    obj = _nvd(200, tricky=True)
    path = _write(tmp_path / "nvd.json", obj)
    batch = feeds.parse_feed("nvd.json", Path(path).read_bytes())
    stream = list(feeds.iter_records_from_path(path, "nvd.json"))
    assert stream == batch
    assert len(stream) == 200


def test_bare_array_format(tmp_path, monkeypatch):
    monkeypatch.setattr(feeds, "_STREAM_CHUNK", 11)
    arr = [{"cve_id": f"CVE-2000-{i:04d}", "product": "p", "severity": "HIGH"} for i in range(30)]
    path = _write(tmp_path / "bare.json", arr)
    assert list(feeds.iter_records_from_path(path, "bare.json")) == feeds.parse_feed(
        "bare.json", Path(path).read_bytes())


def test_cves_key_format(tmp_path, monkeypatch):
    monkeypatch.setattr(feeds, "_STREAM_CHUNK", 29)
    obj = {"cves": [{"cve_id": f"CVE-2001-{i:04d}", "product": "q"} for i in range(40)]}
    path = _write(tmp_path / "internal.json", obj)
    assert list(feeds.iter_records_from_path(path, "internal.json")) == feeds.parse_feed(
        "internal.json", Path(path).read_bytes())


def test_empty_array(tmp_path, monkeypatch):
    monkeypatch.setattr(feeds, "_STREAM_CHUNK", 7)
    path = _write(tmp_path / "empty.json", {"vulnerabilities": []})
    assert list(feeds.iter_records_from_path(path, "empty.json")) == []


def test_csv_stream_matches_batch(tmp_path):
    text = "cve,product,severity\nCVE-2002-1111,Office,HIGH\nCVE-2002-2222,Win,LOW\n"
    path = tmp_path / "f.csv"
    path.write_text(text, encoding="utf-8")
    stream = list(feeds.iter_records_from_path(str(path), "f.csv"))
    assert stream == feeds.parse_feed("f.csv", text.encode())
    assert len(stream) == 2


def test_gzip_json_matches_plain(tmp_path, monkeypatch):
    """`.json.gz` 직접 스트리밍 == 평문 배치 파싱."""
    monkeypatch.setattr(feeds, "_STREAM_CHUNK", 19)
    obj = _nvd(50, tricky=True)
    plain = feeds.parse_feed("nvd.json", json.dumps(obj, ensure_ascii=False).encode("utf-8"))
    gz = tmp_path / "nvd.json.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False)
    assert list(feeds.iter_records_from_path(str(gz), "nvd.json.gz")) == plain


def test_gzip_csv(tmp_path):
    text = "cve,severity\nCVE-2003-1234,LOW\n"
    gz = tmp_path / "f.csv.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as f:
        f.write(text)
    recs = list(feeds.iter_records_from_path(str(gz), "f.csv.gz"))
    assert len(recs) == 1 and recs[0]["cve_id"] == "CVE-2003-1234"


def test_unsupported_format_raises(tmp_path):
    path = tmp_path / "x.json"
    path.write_text('{"foo": 1}', encoding="utf-8")
    with pytest.raises(ValueError):
        list(feeds.iter_records_from_path(str(path), "x.json"))
