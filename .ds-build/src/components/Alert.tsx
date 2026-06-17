import React from "react";

export type AlertTone = "info" | "warning" | "danger" | "success";

interface AlertStyle { bg: string; border: string; leftBar?: string; fg: string; icon: React.ReactNode; }

const stroke = (color: string) => ({ stroke: color, strokeWidth: 1.7, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, fill: "none" as const });

function infoIcon(c: string) {
  return <svg width="20" height="20" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" {...stroke(c)} /><path d="M12 8v5m0 3h.01" {...stroke(c)} /></svg>;
}
function warnIcon(c: string) {
  return <svg width="20" height="20" viewBox="0 0 24 24"><path d="M12 3 2 20h20L12 3Z" {...stroke(c)} /><path d="M12 10v4m0 3h.01" {...stroke(c)} /></svg>;
}
function checkIcon(c: string) {
  return <svg width="20" height="20" viewBox="0 0 24 24"><path d="M20 6 9 17l-5-5" {...stroke(c)} /></svg>;
}

const TONES: Record<AlertTone, AlertStyle> = {
  info: { bg: "var(--ds-color-success-tint)", border: "var(--ds-color-success-border)", fg: "var(--ds-color-primary-strong)", icon: infoIcon("var(--ds-color-primary)") },
  success: { bg: "var(--ds-color-success-tint)", border: "var(--ds-color-success-border)", fg: "var(--ds-color-primary-strong)", icon: checkIcon("var(--ds-color-primary)") },
  warning: { bg: "var(--ds-color-warning-tint)", border: "var(--ds-color-warning-border)", leftBar: "var(--ds-color-warning-accent)", fg: "var(--ds-color-warning-strong)", icon: warnIcon("var(--ds-color-warning)") },
  danger: { bg: "var(--ds-color-danger-tint)", border: "var(--ds-color-danger-border)", leftBar: "var(--ds-color-danger)", fg: "var(--ds-color-danger-text)", icon: warnIcon("var(--ds-color-danger)") },
};

export interface AlertProps {
  tone?: AlertTone;
  /** Bolded lead text. */
  title?: React.ReactNode;
  children?: React.ReactNode;
  /** Optional trailing action (e.g. a Button). */
  action?: React.ReactNode;
}

/** Inline callout banner — info / warning / danger / success. */
export function Alert({ tone = "info", title, children, action }: AlertProps) {
  const t = TONES[tone];
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: 12,
        background: t.bg,
        border: `1px solid ${t.border}`,
        borderLeft: t.leftBar ? `3px solid ${t.leftBar}` : `1px solid ${t.border}`,
        borderRadius: "var(--ds-radius-lg)",
        padding: "13px 18px",
      }}
    >
      <span style={{ flexShrink: 0, display: "flex" }}>{t.icon}</span>
      <div style={{ flex: 1, fontSize: 13, lineHeight: 1.55, color: t.fg }}>
        {title && <span style={{ fontWeight: 700 }}>{title} </span>}
        {children}
      </div>
      {action && <span style={{ flexShrink: 0 }}>{action}</span>}
    </div>
  );
}
