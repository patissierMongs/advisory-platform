import React from "react";
export interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
    /** Inner padding. Defaults to 20px (the app's standard card padding). */
    padding?: number | string;
    /** Drop the border + radius, e.g. when nesting inside another surface. */
    flush?: boolean;
    children?: React.ReactNode;
}
/** The base white surface used for every panel in the app. */
export declare function Card({ padding, flush, style, children, ...rest }: CardProps): React.JSX.Element;
