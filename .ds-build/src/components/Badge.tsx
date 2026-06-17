import React from "react";

export type BadgeTone = "primary" | "danger" | "warning" | "info" | "success" | "purple" | "neutral";

interface ToneColors { fg: string; bg: string; border: string; }

export const BADGE_TONES: Record<BadgeTone, ToneColors> = {
  primary: { fg: "var(--ds-color-primary)", bg: "var(--ds-color-primary-tint)", border: "var(--ds-color-primary-border)" },
  danger: { fg: "var(--ds-color-danger)", bg: "var(--ds-color-danger-tint)", border: "var(--ds-color-danger-border)" },
  warning: { fg: "var(--ds-color-warning-text)", bg: "var(--ds-color-warning-tint-2)", border: "var(--ds-color-warning-border)" },
  info: { fg: "var(--ds-color-info)", bg: "var(--ds-color-info-tint)", border: "var(--ds-color-info-border)" },
  success: { fg: "var(--ds-color-primary)", bg: "var(--ds-color-success-tint)", border: "var(--ds-color-success-border)" },
  purple: { fg: "var(--ds-color-purple)", bg: "var(--ds-color-purple-tint)", border: "var(--ds-color-purple-border)" },
  neutral: { fg: "var(--ds-color-text-muted)", bg: "var(--ds-color-surface-alt)", border: "var(--ds-color-border-field)" },
};

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  tone?: BadgeTone;
  /** "soft" = tinted fill (default); "solid" = filled with the tone color. */
  variant?: "soft" | "solid";
  /** Show a leading status dot. */
  dot?: boolean;
  children?: React.ReactNode;
}

/** Small status / label pill. Soft tinted by default, like the app's status tags. */
export function Badge({ tone = "neutral", variant = "soft", dot = false, style, children, ...rest }: BadgeProps) {
  const c = BADGE_TONES[tone];
  const solid = variant === "solid";
  return (
    <span
      {...rest}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: 5,
        fontSize: 11,
        fontWeight: 600,
        lineHeight: 1.4,
        padding: "3px 9px",
        borderRadius: "var(--ds-radius-sm)",
        color: solid ? "#fff" : c.fg,
        background: solid ? c.fg : c.bg,
        border: solid ? "none" : `1px solid ${c.border}`,
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {dot && (
        <span
          style={{
            width: 6,
            height: 6,
            borderRadius: "50%",
            background: solid ? "#fff" : c.fg,
            flexShrink: 0,
          }}
        />
      )}
      {children}
    </span>
  );
}
