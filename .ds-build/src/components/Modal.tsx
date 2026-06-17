import React from "react";

export interface ModalProps {
  open: boolean;
  onClose?: () => void;
  title?: React.ReactNode;
  subtitle?: React.ReactNode;
  /** Optional icon left of the title. */
  icon?: React.ReactNode;
  footer?: React.ReactNode;
  width?: number;
  children?: React.ReactNode;
}

/** Centered overlay dialog (e.g. the PDF viewer). Renders nothing when closed. */
export function Modal({ open, onClose, title, subtitle, icon, footer, width = 600, children }: ModalProps) {
  if (!open) return null;
  return (
    <div
      className="ads-modal-overlay"
      onClick={onClose}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(15,29,46,.55)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 80,
        padding: 40,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width,
          maxWidth: "100%",
          maxHeight: "84vh",
          background: "var(--ds-color-surface)",
          borderRadius: "var(--ds-radius-2xl)",
          overflow: "hidden",
          display: "flex",
          flexDirection: "column",
          boxShadow: "var(--ds-shadow-modal)",
        }}
      >
        {(title || icon) && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "15px 20px",
              borderBottom: "1px solid var(--ds-color-border-soft)",
              background: "var(--ds-color-surface-subtle)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: 11, minWidth: 0 }}>
              {icon}
              <div style={{ minWidth: 0 }}>
                {title && <div style={{ fontSize: 13.5, fontWeight: 700, color: "var(--ds-color-text)" }}>{title}</div>}
                {subtitle && <div style={{ fontSize: 11, color: "var(--ds-color-text-faint)", fontFamily: "var(--ds-font-mono)" }}>{subtitle}</div>}
              </div>
            </div>
            {onClose && (
              <button
                type="button"
                onClick={onClose}
                aria-label="close"
                style={{
                  width: 30,
                  height: 30,
                  borderRadius: "var(--ds-radius-sm)",
                  background: "#fff",
                  border: "1px solid var(--ds-color-border)",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  flexShrink: 0,
                }}
              >
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none">
                  <path d="M6 6l12 12M18 6L6 18" stroke="var(--ds-color-text-muted)" strokeWidth="1.8" strokeLinecap="round" />
                </svg>
              </button>
            )}
          </div>
        )}
        <div className="ads-scroll" style={{ padding: "24px 28px", overflowY: "auto", flex: 1 }}>
          {children}
        </div>
        {footer && (
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 10, padding: "13px 20px", borderTop: "1px solid var(--ds-color-border-soft)" }}>
            {footer}
          </div>
        )}
      </div>
    </div>
  );
}
