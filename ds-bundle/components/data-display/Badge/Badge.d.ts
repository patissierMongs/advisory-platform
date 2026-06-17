import React from "react";
export type BadgeTone = "primary" | "danger" | "warning" | "info" | "success" | "purple" | "neutral";
interface ToneColors {
    fg: string;
    bg: string;
    border: string;
}
export declare const BADGE_TONES: Record<BadgeTone, ToneColors>;
export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
    tone?: BadgeTone;
    /** "soft" = tinted fill (default); "solid" = filled with the tone color. */
    variant?: "soft" | "solid";
    /** Show a leading status dot. */
    dot?: boolean;
    children?: React.ReactNode;
}
/** Small status / label pill. Soft tinted by default, like the app's status tags. */
export declare function Badge({ tone, variant, dot, style, children, ...rest }: BadgeProps): React.JSX.Element;
export {};
