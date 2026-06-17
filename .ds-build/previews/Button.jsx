import React from "react";
import { Button } from "./ds";

export const meta = { group: "Actions", width: 520, height: 180, subtitle: "primary / dark / danger / secondary / ghost" };

export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 28, display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", gap: 10, flexWrap: "wrap", alignItems: "center" }}>
        <Button variant="primary">파일 선택</Button>
        <Button variant="dark">전체 부서 일괄 발송</Button>
        <Button variant="danger">발송</Button>
        <Button variant="secondary">← 이전</Button>
        <Button variant="ghost">+ 추가</Button>
      </div>
      <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
        <Button size="sm" variant="primary">작게</Button>
        <Button size="sm" variant="secondary">취소</Button>
        <Button variant="primary" disabled>비활성</Button>
      </div>
    </div>
  );
}
