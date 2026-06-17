import React from "react";
export interface DropzoneProps {
    /** Big icon shown in the tinted circle. Defaults to an upload arrow. */
    icon?: React.ReactNode;
    title?: React.ReactNode;
    hint?: React.ReactNode;
    /** Label for the inline pick button; omit to hide it. */
    buttonLabel?: React.ReactNode;
    onPick?: () => void;
    onDragOver?: React.DragEventHandler;
    onDrop?: React.DragEventHandler;
    /** Smaller padding variant. */
    compact?: boolean;
}
/** Dashed file-drop area with icon, title, hint and an optional pick button. */
export declare function Dropzone({ icon, title, hint, buttonLabel, onPick, onDragOver, onDrop, compact }: DropzoneProps): React.JSX.Element;
