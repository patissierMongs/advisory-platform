import React from "react";
import { SeverityBadge } from "./ds";

export const meta = { group: "Data Display", width: 460, height: 120, subtitle: "critical / high / medium / low" };

export default function Preview() {
  return (
    <div className="ads-root" style={{ padding: 28, display: "flex", gap: 12, alignItems: "center" }}>
      <SeverityBadge level="critical" />
      <SeverityBadge level="high" />
      <SeverityBadge level="medium" />
      <SeverityBadge level="low" />
      <SeverityBadge level="critical" label="CRITICAL" />
    </div>
  );
}
