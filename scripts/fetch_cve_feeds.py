"""공개 CVE 소스 수집 → app/core/feeds.py 가 ingest 하는 형식으로 samples/cve_feeds/ 에 저장.

소스(공공기관·폐쇄망 안전 라이선스만):
  · NVD 2.0 API   — 미국 NIST, Public Domain. CPE→제품/버전규칙 + CVSS. NVD JSON 그대로 적재.
  · CISA KEV      — 미국 CISA, Public Domain. 알려진 악용 취약점. 내부 JSON 으로 변환.
  · KISA(한국)    — hancom 등 국내 제품은 NVD 미수록 → 기존 samples 의 KISA 피드로 보완.

매칭 대상 제품군은 app/core/normalize.py 의 product_key 사전과 일치시킨다.
재실행으로 갱신 가능. 외부 라이브러리 0(stdlib urllib). NVD 무인증 레이트리밋(5req/30s) 준수.

사용: python scripts/fetch_cve_feeds.py
"""
from __future__ import annotations

import json
import time
import urllib.parse
import urllib.request
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples" / "cve_feeds"
OUT.mkdir(parents=True, exist_ok=True)

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
PAGE = 2000
SLEEP = 6.5      # NVD 무인증 5req/30s → 1req/6.5s 안전
MAX_PAGES = 12   # 폭주 방지(제품당 최대 24,000건)

# normalize.py 매칭 제품군 → NVD CPE(vendor:product). virtualMatchString 으로 버전 무관 전체 매칭.
PRODUCTS = [
    ("windows_11", "cpe:2.3:o:microsoft:windows_11"),
    ("windows_10", "cpe:2.3:o:microsoft:windows_10"),
    ("windows_server_2022", "cpe:2.3:o:microsoft:windows_server_2022"),
    ("windows_server_2019", "cpe:2.3:o:microsoft:windows_server_2019"),
    ("windows_server_2016", "cpe:2.3:o:microsoft:windows_server_2016"),
    ("microsoft_office", "cpe:2.3:a:microsoft:office"),
    ("microsoft_365_apps", "cpe:2.3:a:microsoft:365_apps"),
    ("edge", "cpe:2.3:a:microsoft:edge"),
    ("google_chrome", "cpe:2.3:a:google:chrome"),
    ("adobe_acrobat_reader", "cpe:2.3:a:adobe:acrobat_reader"),
    ("adobe_acrobat", "cpe:2.3:a:adobe:acrobat"),
    ("linux_kernel", "cpe:2.3:o:linux:linux_kernel"),
    ("ubuntu", "cpe:2.3:o:canonical:ubuntu_linux"),
    ("ibm_aix", "cpe:2.3:o:ibm:aix"),
    ("openssl", "cpe:2.3:a:openssl:openssl"),
    ("apache_httpd", "cpe:2.3:a:apache:http_server"),
    ("nginx", "cpe:2.3:a:f5:nginx"),
]


def _get(url: str, tries: int = 4):
    for i in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "advisory-platform-feedfetch"})
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"    retry {i + 1}/{tries}: {e}", flush=True)
            time.sleep(SLEEP * 2)
    return None


def fetch_nvd(key: str, vm: str) -> int:
    vulns: list = []
    start = pages = 0
    total = None
    while pages < MAX_PAGES:
        url = f"{NVD}?virtualMatchString={urllib.parse.quote(vm)}&resultsPerPage={PAGE}&startIndex={start}"
        d = _get(url)
        time.sleep(SLEEP)
        if not d:
            break
        vs = d.get("vulnerabilities", [])
        vulns.extend(vs)
        total = d.get("totalResults", 0)
        start += PAGE
        pages += 1
        print(f"  [{key}] {len(vulns)}/{total}", flush=True)
        if start >= total or not vs:
            break
    if vulns:
        (OUT / f"nvd_{key}.json").write_text(json.dumps({"vulnerabilities": vulns}), encoding="utf-8")
    return len(vulns)


def fetch_kev() -> int:
    d = _get(KEV)
    if not d:
        return 0
    cves = []
    for v in d.get("vulnerabilities", []):
        cves.append({
            "cve_id": v.get("cveID"),
            "product_name": (f"{v.get('vendorProject', '')} {v.get('product', '')}").strip(),
            "severity": "HIGH",  # 알려진 악용 → 중요로 표기(KEV 는 CVSS 미포함)
            "description": v.get("shortDescription") or v.get("vulnerabilityName"),
            "published": v.get("dateAdded"),
            "source": "CISA-KEV",
        })
    (OUT / "cisa_kev.json").write_text(json.dumps({"cves": cves}), encoding="utf-8")
    return len(cves)


if __name__ == "__main__":
    print("[fetch] CISA KEV ...", flush=True)
    print("[fetch] KEV records:", fetch_kev(), flush=True)
    grand = 0
    for key, vm in PRODUCTS:
        grand += fetch_nvd(key, vm)
    print(f"[fetch] DONE - NVD records: {grand} -> {OUT}", flush=True)
