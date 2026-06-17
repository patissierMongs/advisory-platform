import React from "react";
export interface ModalProps {
    open: boolean;
    onClose?: () => void;
    title?: React.ReactNode;
    subtitle?: React.ReactNode;
    /** Optional icon left of the title. */
    icon?: React.ReactNode;
    footer?: React.ReactNode;
    width?: number;
    children?: React.ReactNode;
}
/** Centered overlay dialog (e.g. the PDF viewer). Renders nothing when closed. */
export declare function Modal({ open, onClose, title, subtitle, icon, footer, width, children }: ModalProps): React.JSX.Element | null;
