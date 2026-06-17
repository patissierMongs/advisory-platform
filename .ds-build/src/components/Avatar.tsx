import React from "react";

export interface AvatarProps {
  /** Initials or short text shown inside the circle. */
  initials: React.ReactNode;
  size?: number;
  background?: string;
  /** Optional name + role shown to the right. */
  name?: React.ReactNode;
  role?: React.ReactNode;
}

/** Circular initials avatar, optionally with an identity block. */
export function Avatar({ initials, size = 32, background = "var(--ds-color-primary)", name, role }: AvatarProps) {
  const circle = (
    <div
      style={{
        width: size,
        height: size,
        borderRadius: "50%",
        background,
        color: "#fff",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: Math.round(size * 0.375),
        fontWeight: 700,
        flexShrink: 0,
      }}
    >
      {initials}
    </div>
  );
  if (name == null && role == null) return circle;
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
      {circle}
      <div style={{ lineHeight: 1.25 }}>
        {name != null && <div style={{ fontSize: 12.5, fontWeight: 600, color: "var(--ds-color-text-strong)" }}>{name}</div>}
        {role != null && <div style={{ fontSize: 11, color: "var(--ds-color-text-faint)" }}>{role}</div>}
      </div>
    </div>
  );
}
