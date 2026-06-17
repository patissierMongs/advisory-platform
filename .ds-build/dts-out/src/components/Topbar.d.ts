import React from "react";
export interface TopbarProps {
    title: React.ReactNode;
    subtitle?: React.ReactNode;
    /** Right-aligned content (status pills, user block, actions). */
    actions?: React.ReactNode;
    children?: React.ReactNode;
}
/** White app header bar: page title + subtitle on the left, actions on the right. */
export declare function Topbar({ title, subtitle, actions, children }: TopbarProps): React.JSX.Element;
