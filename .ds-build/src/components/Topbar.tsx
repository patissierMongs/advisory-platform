import React from "react";

export interface TopbarProps {
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  /** Right-aligned content (status pills, user block, actions). */
  actions?: React.ReactNode;
  children?: React.ReactNode;
}

/** White app header bar: page title + subtitle on the left, actions on the right. */
export function Topbar({ title, subtitle, actions, children }: TopbarProps) {
  return (
    <header
      style={{
        height: 60,
        flexShrink: 0,
        background: "var(--ds-color-surface)",
        borderBottom: "1px solid var(--ds-color-border)",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "0 26px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 11 }}>
        <h1 style={{ margin: 0, fontSize: 17, fontWeight: 700, color: "var(--ds-color-text)", letterSpacing: "-.3px" }}>
          {title}
        </h1>
        {subtitle && <span style={{ fontSize: 12, color: "var(--ds-color-text-soft)", fontWeight: 500 }}>{subtitle}</span>}
      </div>
      <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
        {actions}
        {children}
      </div>
    </header>
  );
}
