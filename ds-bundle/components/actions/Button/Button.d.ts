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
/** Action button. Primary teal by default; matches the app's button family. */
export declare function Button({ variant, size, leftIcon, style, className, children, ...rest }: ButtonProps): React.JSX.Element;
