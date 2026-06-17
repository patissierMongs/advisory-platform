import React from "react";
export type Severity = "critical" | "high" | "medium" | "low";
export interface SeverityBadgeProps {
    level: Severity;
    /** Override the displayed text (defaults to the Korean severity label). */
    label?: React.ReactNode;
}
/** CVE severity badge — maps a severity level to the app's tone + label. */
export declare function SeverityBadge({ level, label }: SeverityBadgeProps): React.JSX.Element;
