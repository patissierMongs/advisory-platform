import React from "react";
export interface StepperProps {
    steps: {
        label: React.ReactNode;
    }[];
    /** Zero-based index of the current step. */
    current: number;
    onStepClick?: (index: number) => void;
}
/** Horizontal numbered stepper with connectors (the advisory 4-step flow). */
export declare function Stepper({ steps, current, onStepClick }: StepperProps): React.JSX.Element;
