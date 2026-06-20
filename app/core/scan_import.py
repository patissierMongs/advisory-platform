"""포트스캔 회차(nmap XML) → 콘솔 레코드 병합.

독립 스캐너(portscan-tool)가 만든 회차 폴더 zip 안의 여러 nmap XML 을 파일명/타입에
의존하지 않고 병합한다: (host, proto, port) 키로 가장 풍부한 정보를 채택
(상태 = Stage2, 서비스/버전/근거 = Stage3, hostname = 디스커버리). 4_unknown/*.txt
배너가 있으면 정체불명 포트에 부착한다. 무손실 원본(XML)을 콘솔이 직접 투영.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

_BANNER_HDR = re.compile(r"^=== (?P<host>.+?):(?P<port>\d+)/(?P<proto>tcp|udp) ===\s*$")


def parse_banner_txt(text: str) -> dict[tuple[str, str, int], str]:
    """4_unknown/<host>.txt → {(host, proto, port): banner}."""
    out: dict[tuple[str, str, int], str] = {}
    cur: tuple[str, str, int] | None = None
    buf: list[str] = []
    for line in text.splitlines():
        m = _BANNER_HDR.match(line)
        if m:
            if cur is not None:
                out[cur] = "\n".join(buf).strip()
            cur = (m.group("host"), m.group("proto"), int(m.group("port")))
            buf = []
        elif cur is not None:
            buf.append(line)
    if cur is not None:
        out[cur] = "\n".join(buf).strip()
    return out


def _summarize_scripts(scripts: dict[str, str]) -> str | None:
    bits = []
    for sid, out in scripts.items():
        o = " ".join((out or "").split())
        if not o:
            continue
        if len(o) > 140:
            o = o[:140] + "…"
        bits.append(f"{sid}={o}")
    return " | ".join(bits) if bits else None


def parse_scan(xml_blobs: list[bytes],
               banners: dict[tuple[str, str, int], str] | None = None) -> tuple[list[dict], dict]:
    """nmap XML 들 + 배너맵 → (포트 레코드 리스트, 집계). 파일명/타입 무관 병합."""
    banners = banners or {}
    recs: dict[tuple[str, str, int], dict] = {}
    hostnames: dict[str, str] = {}

    for blob in xml_blobs:
        try:
            root = ET.fromstring(blob)
        except ET.ParseError:
            continue
        if root.tag != "nmaprun":
            continue
        for host in root.findall("host"):
            st = host.find("status")
            if st is not None and st.get("state") and st.get("state") != "up":
                continue
            ip = None
            for addr in host.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr")
                    break
            if ip is None:
                a = host.find("address")
                ip = a.get("addr") if a is not None else None
            if not ip:
                continue
            hn = host.find("hostnames/hostname")
            if hn is not None and hn.get("name"):
                hostnames.setdefault(ip, hn.get("name"))
            ports = host.find("ports")
            if ports is None:
                continue
            for p in ports.findall("port"):
                pstate = p.find("state")
                if pstate is None or "open" not in (pstate.get("state") or ""):
                    continue
                proto = p.get("protocol")
                portid = int(p.get("portid"))
                key = (ip, proto, portid)
                rec = recs.get(key)
                if rec is None:
                    rec = {"host": ip, "proto": proto, "port": portid,
                           "state": pstate.get("state"), "reason": pstate.get("reason"),
                           "service": None, "product": None, "version": None, "extra": None,
                           "tunnel": None, "method": None, "_scripts": {}}
                    recs[key] = rec
                elif rec["state"] != "open" and pstate.get("state") == "open":
                    rec["state"] = "open"            # 'open' 이 'open|filtered' 보다 확실
                    rec["reason"] = pstate.get("reason")
                svc = p.find("service")
                if svc is not None:
                    for field, attr in (("service", "name"), ("product", "product"),
                                        ("version", "version"), ("extra", "extrainfo"),
                                        ("tunnel", "tunnel")):
                        v = svc.get(attr)
                        if v and not rec[field]:
                            rec[field] = v
                    # method: 'probed'(실측 -sV) 가 'table'(포트번호 추측) 보다 우선.
                    if svc.get("method") == "probed" or not rec["method"]:
                        rec["method"] = svc.get("method")
                for sc in p.findall("script"):
                    sid, out = sc.get("id"), sc.get("output")
                    if sid and out:
                        rec["_scripts"][sid] = out

    records = []
    for rec in recs.values():
        rec["evidence"] = _summarize_scripts(rec.pop("_scripts"))
        b = banners.get((rec["host"], rec["proto"], rec["port"]))
        rec["banner"] = (" ".join(b.split())[:300]) if b else None
        rec["hostname"] = hostnames.get(rec["host"])
        # TLS 터널 보정 — name=http + tunnel=ssl 은 실제 https (nmap 표기 습관).
        if rec["tunnel"] == "ssl" and rec["service"] == "http":
            rec["service"] = "https"
        probed = rec.pop("method") == "probed"
        rec.pop("tunnel", None)
        named = rec["service"] and rec["service"] not in ("unknown", "tcpwrapped")
        if rec["product"] or rec["version"]:
            # 실제 제품/버전 확보 = 프로그램 식별 완료.
            rec["identified"], rec["note"] = "Y", None
        elif rec["banner"] or rec["evidence"] or (probed and named):
            # 프로토콜/근거는 있으나 프로그램 미확정 → 사람 판독 필요.
            rec["identified"] = "P"
            rec["note"] = "배너 확보 — 판독 필요" if rec["banner"] else "서비스 추정 — 프로그램 미확정"
        else:
            # 아무 근거 없음(또는 포트번호 추측만) → 정체불명.
            rec["identified"], rec["note"] = "N", "정체불명 — 벤더 확인 필요"
        records.append(rec)

    records.sort(key=lambda r: (r["host"], r["proto"], r["port"]))
    counts = {
        "host_count": len({r["host"] for r in records}),
        "open_port_count": len(records),
        "identified_count": sum(1 for r in records if r["identified"] == "Y"),
    }
    return records, counts
