import React from "react";
import { Chip } from "./ds";

export const meta = { group: "Data Display", width: 520, height: 140, subtitle: "removable tokens (extracted CVEs)" };

export default function Preview() {
  const codes = ["CVE-2024-21413", "CVE-2024-38063", "CVE-2023-44487", "CVE-2024-3094"];
  return (
    <div className="ads-root" style={{ padding: 28 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
        <span style={{ fontSize: 11, color: "var(--ds-color-text-faint)", fontWeight: 600 }}>추출된 CVE</span>
        {codes.map((c) => (
          <Chip key={c} mono onRemove={() => {}}>{c}</Chip>
        ))}
      </div>
    </div>
  );
}
