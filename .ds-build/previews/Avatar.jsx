import React from "react";
import { Avatar } from "./ds";

export const meta = { group: "Data Display", width: 460, height: 140, subtitle: "initials circle + identity" };

export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 28, display: "flex", gap: 26, alignItems: "center" }}>
      <Avatar initials="관제" />
      <Avatar initials="JS" size={40} background="var(--ds-color-navy)" />
      <Avatar initials="관제" name="정보보호팀 · 관제" role="보안관제 담당" />
    </div>
  );
}
