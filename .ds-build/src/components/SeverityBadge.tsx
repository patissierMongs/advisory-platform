import React from "react";
import { Badge, BadgeTone } from "./Badge";

export type Severity = "critical" | "high" | "medium" | "low";

const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  critical: "danger",
  high: "warning",
  medium: "info",
  low: "neutral",
};

/** Korean labels as used in the source app. */
const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "긴급",
  high: "높음",
  medium: "보통",
  low: "낮음",
};

export interface SeverityBadgeProps {
  level: Severity;
  /** Override the displayed text (defaults to the Korean severity label). */
  label?: React.ReactNode;
}

/** CVE severity badge — maps a severity level to the app's tone + label. */
export function SeverityBadge({ level, label }: SeverityBadgeProps) {
  return (
    <Badge tone={SEVERITY_TONE[level]} variant="soft" style={{ justifyContent: "center", minWidth: 42 }}>
      {label ?? SEVERITY_LABEL[level]}
    </Badge>
  );
}
