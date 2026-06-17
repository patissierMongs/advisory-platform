import React from "react";
import { Card } from "./ds";

export const meta = { group: "Layout", width: 520, height: 240, subtitle: "Base white surface" };

export default function Preview() {
  return (
    <div className="ads-root" style={{ display: "grid", gridTemplateColumns: "1.4fr 1fr", gap: 18, padding: 24 }}>
      <Card>
        <h2 style={{ margin: "0 0 4px", fontSize: 15, fontWeight: 700, color: "var(--ds-color-text)" }}>보안권고문 PDF 업로드</h2>
        <p style={{ margin: 0, fontSize: 13, color: "var(--ds-color-text-soft)" }}>
          PDF에서 CVE 코드만 자동 추출합니다. 제품·버전 정보는 로컬 CVE DB에서 조회합니다.
        </p>
      </Card>
      <Card padding="22px">
        <h3 style={{ margin: "0 0 6px", fontSize: 13.5, fontWeight: 700, color: "var(--ds-color-text)" }}>데이터베이스 상태</h3>
        <div style={{ fontSize: 12.5, color: "var(--ds-color-text-soft)" }}>등록 CVE 1,284건 · 마지막 갱신 06:00</div>
      </Card>
    </div>
  );
}
