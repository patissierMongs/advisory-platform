import { SeverityBadge } from "advisory-platform-ds";


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
