import React from "react";
import { StatCard } from "./ds";

export const meta = { group: "Data Display", width: 560, height: 150, subtitle: "metric tiles" };

export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 24, display: "grid", gridTemplateColumns: "repeat(3,1fr)", gap: 16 }}>
      <StatCard label="추출 CVE" value="12" unit="건" />
      <StatCard label="DB 조회완료" value="9" unit="건" valueColor="var(--ds-color-primary)" />
      <StatCard label="DB 미등록" value="3" unit="건" valueColor="var(--ds-color-warning)" />
    </div>
  );
}
