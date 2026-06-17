import React from "react";
import { Badge } from "./ds";

export const meta = { group: "Data Display", width: 520, height: 180, subtitle: "tones · soft / solid / dot" };

export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 28, display: "flex", flexDirection: "column", gap: 14 }}>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <Badge tone="primary">처리중</Badge>
        <Badge tone="danger">긴급</Badge>
        <Badge tone="warning">DB 미등록</Badge>
        <Badge tone="info">NVD</Badge>
        <Badge tone="success">완료</Badge>
        <Badge tone="purple">KISA 공지</Badge>
        <Badge tone="neutral">대기</Badge>
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
        <Badge tone="primary" variant="solid">NEW</Badge>
        <Badge tone="danger" variant="solid">9건</Badge>
        <Badge tone="primary" dot>로컬 처리</Badge>
        <Badge tone="neutral" dot>오프라인</Badge>
      </div>
    </div>
  );
}
