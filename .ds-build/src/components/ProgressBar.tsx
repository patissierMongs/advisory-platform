import React from "react";

export interface ProgressBarProps {
  /** 0–100. */
  value: number;
  /** Bar fill color. Defaults to primary teal. */
  color?: string;
  /** Optional label + percentage row above the track. */
  label?: React.ReactNode;
  /** Show the numeric percentage on the right of the label row. */
  showValue?: boolean;
  height?: number;
}

/** Thin progress track, e.g. per-department remediation progress. */
export function ProgressBar({ value, color = "var(--ds-color-primary)", label, showValue = true, height = 7 }: ProgressBarProps) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div>
      {(label != null || showValue) && (
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 5 }}>
          {label != null && (
            <span style={{ fontSize: 12.5, color: "var(--ds-color-text-body)", fontWeight: 600 }}>{label}</span>
          )}
          {showValue && <span style={{ fontSize: 12, color: "var(--ds-color-text-faint)" }}>{pct}%</span>}
        </div>
      )}
      <div style={{ height, background: "var(--ds-color-border-soft)", borderRadius: 4, overflow: "hidden" }}>
        <div style={{ width: `${pct}%`, height: "100%", background: color, borderRadius: 4 }} />
      </div>
    </div>
  );
}
