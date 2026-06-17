import React from "react";
export type ToastTone = "primary" | "danger" | "warning" | "info" | "success";
export interface ToastProps {
    title: React.ReactNode;
    children?: React.ReactNode;
    tone?: ToastTone;
    icon?: React.ReactNode;
    onClose?: () => void;
    /** Optional confirm/deny action row. */
    actions?: React.ReactNode;
    /** Render in flow instead of fixed bottom-right (useful for embedding). */
    inline?: boolean;
}
/** Corner notification with a tone accent bar, title, body and optional actions. */
export declare function Toast({ title, children, tone, icon, onClose, actions, inline }: ToastProps): React.JSX.Element;
