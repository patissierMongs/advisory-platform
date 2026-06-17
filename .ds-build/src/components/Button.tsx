import React from "react";

export type ButtonVariant = "primary" | "secondary" | "danger" | "warning" | "ghost" | "dark";
export type ButtonSize = "sm" | "md";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Optional leading icon (svg/element). */
  leftIcon?: React.ReactNode;
  children?: React.ReactNode;
}

const VARIANTS: Record<ButtonVariant, React.CSSProperties> = {
  primary: { background: "var(--ds-color-primary)", color: "#fff", border: "none" },
  dark: { background: "var(--ds-color-navy)", color: "#fff", border: "none" },
  danger: { background: "var(--ds-color-danger)", color: "#fff", border: "none" },
  warning: { background: "var(--ds-color-warning)", color: "#fff", border: "none" },
  secondary: { background: "#fff", color: "var(--ds-color-text-muted)", border: "1px solid var(--ds-color-border-field)" },
  ghost: { background: "#fff", color: "var(--ds-color-primary-strong)", border: "1px solid var(--ds-color-primary-border)" },
};

const SIZES: Record<ButtonSize, React.CSSProperties> = {
  sm: { padding: "6px 13px", fontSize: 11.5 },
  md: { padding: "10px 22px", fontSize: 13 },
};

/** Action button. Primary teal by default; matches the app's button family. */
export function Button({
  variant = "primary",
  size = "md",
  leftIcon,
  style,
  className,
  children,
  ...rest
}: ButtonProps) {
  return (
    <button
      {...rest}
      className={["ads-btn", className].filter(Boolean).join(" ")}
      style={{
        display: "inline-flex",
        alignItems: "center",
        justifyContent: "center",
        gap: 6,
        borderRadius: "var(--ds-radius-md)",
        fontWeight: 600,
        fontFamily: "inherit",
        cursor: "pointer",
        whiteSpace: "nowrap",
        ...SIZES[size],
        ...VARIANTS[variant],
        ...style,
      }}
    >
      {leftIcon}
      {children}
    </button>
  );
}
