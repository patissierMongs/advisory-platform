import React from "react";

export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  /** Inner padding. Defaults to 20px (the app's standard card padding). */
  padding?: number | string;
  /** Drop the border + radius, e.g. when nesting inside another surface. */
  flush?: boolean;
  children?: React.ReactNode;
}

/** The base white surface used for every panel in the app. */
export function Card({ padding = 20, flush = false, style, children, ...rest }: CardProps) {
  return (
    <div
      {...rest}
      style={{
        background: "var(--ds-color-surface)",
        border: flush ? "none" : "1px solid var(--ds-color-border)",
        borderRadius: flush ? 0 : "var(--ds-radius-xl)",
        padding,
        ...style,
      }}
    >
      {children}
    </div>
  );
}
