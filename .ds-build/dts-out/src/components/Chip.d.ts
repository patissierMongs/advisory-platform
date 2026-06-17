import React from "react";
export interface ChipProps {
    children?: React.ReactNode;
    /** When provided, shows an inline remove (×) button. */
    onRemove?: () => void;
    /** Monospace text (used for CVE codes in the app). */
    mono?: boolean;
}
/** Removable token, e.g. the extracted-CVE chips. */
export declare function Chip({ children, onRemove, mono }: ChipProps): React.JSX.Element;
