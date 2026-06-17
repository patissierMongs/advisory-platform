import React from "react";

export type ToastTone = "primary" | "danger" | "warning" | "info" | "success";

const ACCENT: Record<ToastTone, string> = {
  primary: "var(--ds-color-primary)",
  success: "var(--ds-color-primary)",
  danger: "var(--ds-color-danger)",
  warning: "var(--ds-color-warning)",
  info: "var(--ds-color-info)",
};

export interface ToastProps {
  title: React.ReactNode;
  children?: React.ReactNode;
  tone?: ToastTone;
  icon?: React.ReactNode;
  onClose?: () => void;
  /** Optional confirm/deny action row. */
  actions?: React.ReactNode;
  /** Render in flow instead of fixed bottom-right (useful for embedding). */
  inline?: boolean;
}

/** Corner notification with a tone accent bar, title, body and optional actions. */
export function Toast({ title, children, tone = "primary", icon, onClose, actions, inline = false }: ToastProps) {
  return (
    <div
      className="ads-toast"
      style={{
        ...(inline
          ? { position: "relative" as const }
          : { position: "fixed" as const, right: 24, bottom: 24, zIndex: 90 }),
        width: 360,
        background: "var(--ds-color-surface)",
        border: "1px solid var(--ds-color-border)",
        borderLeft: `4px solid ${ACCENT[tone]}`,
        borderRadius: "var(--ds-radius-lg)",
        boxShadow: "var(--ds-shadow-pop)",
        padding: "15px 17px",
      }}
    >
      <div style={{ display: "flex", alignItems: "flex-start", gap: 11 }}>
        {icon && <span style={{ flexShrink: 0, marginTop: 1 }}>{icon}</span>}
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: "var(--ds-color-text)" }}>{title}</div>
          {children && <div style={{ fontSize: 12, color: "var(--ds-color-text-muted)", marginTop: 3, lineHeight: 1.5 }}>{children}</div>}
          {actions && <div style={{ display: "flex", gap: 8, marginTop: 12 }}>{actions}</div>}
        </div>
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            aria-label="close"
            style={{ background: "none", border: "none", cursor: "pointer", padding: 2, flexShrink: 0, display: "flex" }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
              <path d="M6 6l12 12M18 6L6 18" stroke="#aab4c2" strokeWidth="1.8" strokeLinecap="round" />
            </svg>
          </button>
        )}
      </div>
    </div>
  );
}
