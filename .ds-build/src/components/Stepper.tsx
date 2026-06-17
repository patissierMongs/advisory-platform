import React from "react";

export interface StepperProps {
  steps: { label: React.ReactNode }[];
  /** Zero-based index of the current step. */
  current: number;
  onStepClick?: (index: number) => void;
}

/** Horizontal numbered stepper with connectors (the advisory 4-step flow). */
export function Stepper({ steps, current, onStepClick }: StepperProps) {
  return (
    <div style={{ display: "flex", alignItems: "center", width: "100%" }}>
      {steps.map((st, i) => {
        const done = i < current;
        const active = i === current;
        const reached = done || active;
        const num = i + 1;
        return (
          <div key={i} style={{ display: "flex", alignItems: "center", flex: 1 }}>
            <button
              type="button"
              onClick={onStepClick ? () => onStepClick(i) : undefined}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 11,
                background: "none",
                border: "none",
                padding: 0,
                cursor: onStepClick ? "pointer" : "default",
                fontFamily: "inherit",
              }}
            >
              <span
                style={{
                  width: 30,
                  height: 30,
                  borderRadius: "50%",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontSize: 13,
                  fontWeight: 700,
                  flexShrink: 0,
                  color: reached ? "#fff" : "var(--ds-color-text-faint)",
                  background: reached ? "var(--ds-color-primary)" : "var(--ds-color-bg)",
                  border: reached ? "none" : "1px solid var(--ds-color-border-field)",
                }}
              >
                {done ? (
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                    <path d="M20 6 9 17l-5-5" stroke="#fff" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                ) : num}
              </span>
              <span style={{ display: "flex", flexDirection: "column", alignItems: "flex-start", lineHeight: 1.2 }}>
                <span style={{ fontSize: 10.5, color: "var(--ds-color-text-faint)", fontWeight: 600 }}>STEP {num}</span>
                <span style={{ fontSize: 13, fontWeight: active ? 700 : 600, color: active ? "var(--ds-color-text)" : "var(--ds-color-text-muted)" }}>
                  {st.label}
                </span>
              </span>
            </button>
            {i < steps.length - 1 && (
              <span
                style={{
                  flex: 1,
                  height: 2,
                  margin: "0 14px",
                  background: i < current ? "var(--ds-color-primary)" : "var(--ds-color-border)",
                  borderRadius: 2,
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
