import React from "react";
import { Card } from "./Card";

export interface StatCardProps {
  label: React.ReactNode;
  value: React.ReactNode;
  unit?: React.ReactNode;
  /** Color of the big number. Defaults to the navy heading color. */
  valueColor?: string;
  /** Compact inline variant (no card chrome) for stat strips inside a row. */
  bare?: boolean;
}

/** Metric tile: small label over a large value + optional unit. */
export function StatCard({ label, value, unit, valueColor = "var(--ds-color-text)", bare = false }: StatCardProps) {
  const body = (
    <>
      <div style={{ fontSize: 12, color: "var(--ds-color-text-soft)", fontWeight: 600 }}>{label}</div>
      <div style={{ display: "flex", alignItems: "baseline", gap: 6, marginTop: bare ? 2 : 8 }}>
        <span style={{ fontSize: bare ? 17 : 28, fontWeight: 800, color: valueColor, letterSpacing: "-.5px" }}>
          {value}
        </span>
        {unit && <span style={{ fontSize: 13, color: "var(--ds-color-text-faint)" }}>{unit}</span>}
      </div>
    </>
  );
  if (bare) return <div>{body}</div>;
  return <Card padding="18px 20px">{body}</Card>;
}
