import React from "react";
export type AlertTone = "info" | "warning" | "danger" | "success";
export interface AlertProps {
    tone?: AlertTone;
    /** Bolded lead text. */
    title?: React.ReactNode;
    children?: React.ReactNode;
    /** Optional trailing action (e.g. a Button). */
    action?: React.ReactNode;
}
/** Inline callout banner — info / warning / danger / success. */
export declare function Alert({ tone, title, children, action }: AlertProps): React.JSX.Element;
