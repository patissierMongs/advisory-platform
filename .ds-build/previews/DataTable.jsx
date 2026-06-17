import React from "react";
import { DataTable, SeverityBadge, Badge } from "./ds";

export const meta = { group: "Data Display", width: 720, height: 280, subtitle: "grid table with badges" };

export default function Preview() {
  const rows = [
    { id: "CVE-2024-21413", product: "Microsoft Outlook", ver: "≤ 16.0.17", sev: "critical", status: "조회완료" },
    { id: "CVE-2024-38063", product: "Windows TCP/IP", ver: "10 / 11", sev: "high", status: "조회완료" },
    { id: "CVE-2023-44487", product: "HTTP/2 (nginx)", ver: "< 1.25.3", sev: "medium", status: "조회완료" },
    { id: "CVE-2024-3094", product: "xz-utils", ver: "5.6.0–5.6.1", sev: "low", status: "미등록" },
  ];
  const columns = [
    { key: "id", header: "CVE", width: "150px", render: (r) => <span style={{ fontFamily: "var(--ds-font-mono)", fontWeight: 600, color: "var(--ds-color-primary-strong)" }}>{r.id}</span> },
    { key: "product", header: "제품 / OS", width: "1fr", render: (r) => <span style={{ fontWeight: 600, color: "var(--ds-color-text-strong)" }}>{r.product}</span> },
    { key: "ver", header: "영향 버전", width: "120px" },
    { key: "sev", header: "심각도", width: "90px", align: "center", render: (r) => <SeverityBadge level={r.sev} /> },
    { key: "status", header: "상태", width: "90px", align: "right", render: (r) => <Badge tone={r.status === "미등록" ? "warning" : "success"}>{r.status}</Badge> },
  ];
  return (
    <div className="ads-root" style={{ padding: 24 }}>
      <DataTable columns={columns} data={rows} getRowKey={(r) => r.id} />
    </div>
  );
}
