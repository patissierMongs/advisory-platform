import React from "react";
export interface StatCardProps {
    label: React.ReactNode;
    value: React.ReactNode;
    unit?: React.ReactNode;
    /** Color of the big number. Defaults to the navy heading color. */
    valueColor?: string;
    /** Compact inline variant (no card chrome) for stat strips inside a row. */
    bare?: boolean;
}
/** Metric tile: small label over a large value + optional unit. */
export declare function StatCard({ label, value, unit, valueColor, bare }: StatCardProps): React.JSX.Element;
