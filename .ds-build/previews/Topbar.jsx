import React from "react";
import { Topbar, Badge, Avatar } from "./ds";

export const meta = { group: "Navigation", width: 760, height: 120, subtitle: "page header with status + user" };

export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 16, background: "var(--ds-color-bg)" }}>
      <Topbar
        title="권고문 처리"
        subtitle="CVE 추출 · 조회"
        actions={
          <>
            <Badge tone="primary" dot style={{ background: "var(--ds-color-surface-alt)", border: "1px solid var(--ds-color-border)", color: "var(--ds-color-text-body)", padding: "6px 11px" }}>
              로컬 처리 · 오프라인
            </Badge>
            <Avatar initials="관제" name="정보보호팀 · 관제" role="보안관제 담당" />
          </>
        }
      />
    </div>
  );
}
