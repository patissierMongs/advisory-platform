import React from "react";
import { Sidebar } from "./ds";

export const meta = { group: "Navigation", width: 300, height: 460, subtitle: "nav rail with brand + items" };

const ic = (d) => <svg width="17" height="17" viewBox="0 0 24 24" fill="none"><path d={d} stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>;

export default function Preview() {
  const brand = {
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M12 2 4 5v6c0 4.5 3.2 8.5 8 10 4.8-1.5 8-5.5 8-10V5l-8-3Z" stroke="#fff" strokeWidth="1.7" strokeLinejoin="round" /><path d="m8.5 12 2.4 2.4 4.6-4.8" stroke="#fff" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" /></svg>,
    title: "보안권고문 처리",
    subtitle: "취약점 대응 워크플로우",
  };
  const items = [
    { label: "권고문 처리", icon: ic("M9 5H7a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2h-2M9 5a2 2 0 0 0 2 2h2a2 2 0 0 0 2-2"), active: true, badge: "3" },
    { label: "CVE 데이터베이스", icon: ic("M4 7c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3Zm0 0v10c0 1.7 3.6 3 8 3s8-1.3 8-3V7") },
    { label: "자산대장", icon: ic("M3 9h18M9 21V9M3 5h18v14H3z") },
    { label: "발송 이력", icon: ic("M22 2 11 13M22 2l-7 20-4-9-9-4 20-7Z") },
    { label: "대시보드", icon: ic("M3 3h8v8H3zM13 3h8v5h-8zM13 12h8v9h-8zM3 15h8v6H3z") },
  ];
  const footer = (
    <div>
      <div style={{ fontSize: 11, color: "#7d93ad", marginBottom: 7 }}>평가 대응 마감</div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 7 }}>
        <span style={{ fontSize: 22, fontWeight: 800, color: "var(--ds-color-primary-accent)" }}>D-12</span>
        <span style={{ fontSize: 12, color: "#9fb1c6" }}>2026. 6. 26.</span>
      </div>
    </div>
  );
  return (
    <div className="ads-root" style={{ height: 460 }}>
      <Sidebar brand={brand} items={items} footer={footer} />
    </div>
  );
}
