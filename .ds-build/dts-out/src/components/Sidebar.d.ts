import React from "react";
export interface NavItemProps {
    label: React.ReactNode;
    icon?: React.ReactNode;
    badge?: React.ReactNode;
    active?: boolean;
    onClick?: () => void;
}
/** A single sidebar navigation row. */
export declare function NavItem({ label, icon, badge, active, onClick }: NavItemProps): React.JSX.Element;
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
export declare function Sidebar({ brand, items, footer, width, children }: SidebarProps): React.JSX.Element;
