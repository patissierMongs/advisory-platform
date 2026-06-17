import React from "react";
export interface ProgressBarProps {
    /** 0–100. */
    value: number;
    /** Bar fill color. Defaults to primary teal. */
    color?: string;
    /** Optional label + percentage row above the track. */
    label?: React.ReactNode;
    /** Show the numeric percentage on the right of the label row. */
    showValue?: boolean;
    height?: number;
}
/** Thin progress track, e.g. per-department remediation progress. */
export declare function ProgressBar({ value, color, label, showValue, height }: ProgressBarProps): React.JSX.Element;
