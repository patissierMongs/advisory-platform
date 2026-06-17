import React from "react";
import { Badge } from "./Badge";

export interface NavItemProps {
  label: React.ReactNode;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  active?: boolean;
  onClick?: () => void;
}

/** A single sidebar navigation row. */
export function NavItem({ label, icon, badge, active = false, onClick }: NavItemProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="ads-navitem"
      style={{
        display: "flex",
        alignItems: "center",
        gap: 11,
        width: "100%",
        padding: "10px 12px",
        borderRadius: "var(--ds-radius-md)",
        border: "none",
        cursor: "pointer",
        fontSize: 13,
        fontFamily: "inherit",
        fontWeight: active ? 700 : 500,
        textAlign: "left",
        background: active ? "rgba(95,208,196,.12)" : "transparent",
        color: active ? "#fff" : "#cdd8e6",
      }}
    >
      <span style={{ display: "flex", width: 20, justifyContent: "center", flexShrink: 0 }}>{icon}</span>
      <span style={{ flex: 1 }}>{label}</span>
      {badge != null && <Badge tone="primary" variant="solid">{badge}</Badge>}
    </button>
  );
}

export interface SidebarBrand {
  icon?: React.ReactNode;
  title: React.ReactNode;
  subtitle?: React.ReactNode;
}

export interface SidebarProps {
  brand?: SidebarBrand;
  items?: NavItemProps[];
  footer?: React.ReactNode;
  width?: number;
  children?: React.ReactNode;
}

/** App navigation rail — dark navy, brand block, nav items, optional footer. */
export function Sidebar({ brand, items, footer, width = 248, children }: SidebarProps) {
  return (
    <aside
      style={{
        width,
        flexShrink: 0,
        background: "var(--ds-color-navy)",
        color: "#cdd8e6",
        display: "flex",
        flexDirection: "column",
        height: "100%",
      }}
    >
      {brand && (
        <div
          style={{
            padding: "20px 20px 18px",
            borderBottom: "1px solid rgba(255,255,255,.08)",
            display: "flex",
            alignItems: "center",
            gap: 11,
          }}
        >
          {brand.icon && (
            <div
              style={{
                width: 34,
                height: 34,
                borderRadius: "var(--ds-radius-md)",
                background: "var(--ds-color-primary)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                flexShrink: 0,
              }}
            >
              {brand.icon}
            </div>
          )}
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: "#fff", letterSpacing: "-.2px" }}>{brand.title}</div>
            {brand.subtitle && <div style={{ fontSize: 11, color: "#7d93ad", marginTop: 1 }}>{brand.subtitle}</div>}
          </div>
        </div>
      )}

      <nav style={{ padding: 12, display: "flex", flexDirection: "column", gap: 3, flex: 1 }}>
        {items?.map((it, i) => <NavItem key={i} {...it} />)}
        {children}
      </nav>

      {footer && <div style={{ padding: 16, borderTop: "1px solid rgba(255,255,255,.08)" }}>{footer}</div>}
    </aside>
  );
}
