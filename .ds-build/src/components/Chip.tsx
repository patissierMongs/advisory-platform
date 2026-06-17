import React from "react";

export interface ChipProps {
  children?: React.ReactNode;
  /** When provided, shows an inline remove (×) button. */
  onRemove?: () => void;
  /** Monospace text (used for CVE codes in the app). */
  mono?: boolean;
}

/** Removable token, e.g. the extracted-CVE chips. */
export function Chip({ children, onRemove, mono = false }: ChipProps) {
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 6,
        fontSize: 11.5,
        fontWeight: 600,
        fontFamily: mono ? "var(--ds-font-mono)" : "inherit",
        color: "var(--ds-color-primary-strong)",
        background: "var(--ds-color-primary-tint)",
        border: "1px solid var(--ds-color-primary-border)",
        borderRadius: "var(--ds-radius-sm)",
        padding: "4px 9px",
      }}
    >
      {children}
      {onRemove && (
        <button
          type="button"
          onClick={onRemove}
          aria-label="remove"
          style={{
            background: "none",
            border: "none",
            cursor: "pointer",
            padding: 0,
            display: "flex",
            color: "inherit",
            opacity: 0.55,
          }}
        >
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none">
            <path d="M6 6l12 12M18 6L6 18" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" />
          </svg>
        </button>
      )}
    </span>
  );
}
