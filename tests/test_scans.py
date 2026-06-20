"""포트스캔 회차 import/조회/diff — nmap XML zip 병합 라우트 테스트."""
from __future__ import annotations

import io
import zipfile

NS = '<?xml version="1.0"?>'


def _disc(ip, name):
    h = f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
    if name:
        h += f'<hostnames><hostname name="{name}"/></hostnames>'
    return f"{NS}<nmaprun>{h}</host></nmaprun>"


def _ports(ip, ports):
    body = "".join(
        f'<port protocol="tcp" portid="{p}"><state state="open" reason="syn-ack"/></port>'
        for p in ports)
    return (f'{NS}<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
            f"<ports>{body}</ports></host></nmaprun>")


def _ident(ip, svc):
    # svc: {port: (name, product, version)}  (product 빈값이면 미식별)
    body = ""
    for port, (name, prod, ver) in svc.items():
        s = f'<service name="{name}"'
        if prod:
            s += f' product="{prod}"'
        if ver:
            s += f' version="{ver}"'
        s += "/>"
        body += (f'<port protocol="tcp" portid="{port}"><state state="open" reason="syn-ack"/>'
                 f"{s}</port>")
    return (f'{NS}<nmaprun><host><status state="up"/><address addr="{ip}" addrtype="ipv4"/>'
            f"<ports>{body}</ports></host></nmaprun>")


def _zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content)
    return buf.getvalue()


def _import(client, zbytes, label, network):
    return client.post("/api/v1/scans/import",
                       files={"file": (f"{label}.zip", zbytes, "application/zip")},
                       data={"label": label, "network": network})


def test_import_merges_and_identifies(client):
    z = _zip({
        "1_discovery.xml": _disc("10.9.9.1", "app01"),
        "2_ports_tcp.xml": _ports("10.9.9.1", [22, 4444]),
        "3_ident/10.9.9.1_tcp.xml": _ident("10.9.9.1", {22: ("ssh", "OpenSSH", "8.2"),
                                                         4444: ("unknown", "", "")}),
        "4_unknown/10.9.9.1.txt": "=== 10.9.9.1:4444/tcp ===\nWeird-RAT v1 banner\n",
    })
    r = _import(client, z, "r1", "biz")
    assert r.status_code == 201
    run = r.json()["run"]
    rid = run["id"]
    assert run["host_count"] == 1 and run["open_port_count"] == 2
    assert run["identified_count"] == 1            # 22(ssh) 만 Y, 4444 는 배너(P)

    d = client.get(f"/api/v1/scans/{rid}").json()
    by_port = {p["port"]: p for p in d["ports"]}
    assert by_port[22]["identified"] == "Y"
    assert by_port[22]["product"] == "OpenSSH" and by_port[22]["hostname"] == "app01"
    assert by_port[4444]["identified"] == "P"
    assert "Weird-RAT" in by_port[4444]["banner"]
    assert by_port[4444]["note"] and "판독" in by_port[4444]["note"]

    assert any(x["id"] == rid for x in client.get("/api/v1/scans").json()["items"])


def test_diff_tracks_new_and_closed(client):
    z1 = _zip({"2_ports_tcp.xml": _ports("10.9.9.2", [22, 4444]),
               "3_ident/h.xml": _ident("10.9.9.2", {22: ("ssh", "OpenSSH", "8.2"),
                                                     4444: ("unknown", "", "")})})
    id1 = _import(client, z1, "base", "diftest").json()["run"]["id"]

    z2 = _zip({"2_ports_tcp.xml": _ports("10.9.9.2", [22, 8443]),
               "3_ident/h.xml": _ident("10.9.9.2", {22: ("ssh", "OpenSSH", "8.2"),
                                                     8443: ("https", "nginx", "1.18")})})
    id2 = _import(client, z2, "next", "diftest").json()["run"]["id"]

    diff = client.get(f"/api/v1/scans/{id2}/diff").json()
    assert diff["prev_run_id"] == id1
    assert [p["port"] for p in diff["new"]] == [8443]
    assert [p["port"] for p in diff["closed"]] == [4444]


def test_identification_quality(client):
    """tunnel=ssl→https, method=table(포트추측)은 식별 안 함, probed 서비스명만은 P."""
    xml = (f'{NS}<nmaprun><host><status state="up"/><address addr="10.9.9.5" addrtype="ipv4"/><ports>'
           '<port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>'
           '<service name="http" tunnel="ssl" product="nginx" method="probed" conf="10"/></port>'
           '<port protocol="tcp" portid="8080"><state state="open" reason="syn-ack"/>'
           '<service name="http-proxy" method="table" conf="3"/></port>'
           '<port protocol="tcp" portid="7000"><state state="open" reason="syn-ack"/>'
           '<service name="redis" method="probed" conf="10"/></port>'
           '</ports></host></nmaprun>')
    z = _zip({"2_ports.xml": _ports("10.9.9.5", [443, 8080, 7000]), "3_ident/h.xml": xml})
    rid = _import(client, z, "q", "qt").json()["run"]["id"]
    bp = {p["port"]: p for p in client.get(f"/api/v1/scans/{rid}").json()["ports"]}
    assert bp[443]["service"] == "https" and bp[443]["identified"] == "Y"
    assert bp[8080]["identified"] == "N"          # 포트 추측은 식별 아님
    assert bp[7000]["identified"] == "P"          # 프로토콜만 알고 프로그램 미확정


def test_import_rejects_non_zip_and_empty(client):
    assert client.post("/api/v1/scans/import",
                       files={"file": ("x.zip", b"not a zip", "application/zip")},
                       data={"label": "x", "network": ""}).status_code == 400
    empty = _zip({"readme.txt": "no xml here"})
    assert _import(client, empty, "e", "").status_code == 400
