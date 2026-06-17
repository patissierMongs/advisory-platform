import React from "react";

export interface DropzoneProps {
  /** Big icon shown in the tinted circle. Defaults to an upload arrow. */
  icon?: React.ReactNode;
  title?: React.ReactNode;
  hint?: React.ReactNode;
  /** Label for the inline pick button; omit to hide it. */
  buttonLabel?: React.ReactNode;
  onPick?: () => void;
  onDragOver?: React.DragEventHandler;
  onDrop?: React.DragEventHandler;
  /** Smaller padding variant. */
  compact?: boolean;
}

const defaultIcon = (
  <svg width="26" height="26" viewBox="0 0 24 24" fill="none">
    <path d="M12 16V4m0 0L7 9m5-5 5 5" stroke="var(--ds-color-primary)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    <path d="M4 17v2a1 1 0 0 0 1 1h14a1 1 0 0 0 1-1v-2" stroke="var(--ds-color-primary)" strokeWidth="1.8" strokeLinecap="round" />
  </svg>
);

/** Dashed file-drop area with icon, title, hint and an optional pick button. */
export function Dropzone({ icon = defaultIcon, title, hint, buttonLabel, onPick, onDragOver, onDrop, compact = false }: DropzoneProps) {
  return (
    <div
      onDragOver={onDragOver}
      onDrop={onDrop}
      style={{
        border: "2px dashed #c4d0de",
        borderRadius: "var(--ds-radius-xl)",
        background: "var(--ds-color-surface-muted)",
        padding: compact ? "30px 20px" : "46px 20px",
        textAlign: "center",
      }}
    >
      <div
        style={{
          width: compact ? 48 : 54,
          height: compact ? 48 : 54,
          margin: "0 auto 12px",
          borderRadius: "var(--ds-radius-2xl)",
          background: "var(--ds-color-primary-tint)",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
        }}
      >
        {icon}
      </div>
      {title && <div style={{ fontSize: compact ? 13 : 14, fontWeight: 600, color: "var(--ds-color-text-body)" }}>{title}</div>}
      {hint && <div style={{ fontSize: 11.5, color: "var(--ds-color-text-faint)", marginTop: 5 }}>{hint}</div>}
      {buttonLabel && (
        <button
          type="button"
          onClick={onPick}
          className="ads-btn"
          style={{
            marginTop: 16,
            background: "var(--ds-color-primary)",
            color: "#fff",
            border: "none",
            borderRadius: "var(--ds-radius-md)",
            padding: "10px 22px",
            fontSize: 13,
            fontWeight: 600,
            cursor: "pointer",
            fontFamily: "inherit",
          }}
        >
          {buttonLabel}
        </button>
      )}
    </div>
  );
}
