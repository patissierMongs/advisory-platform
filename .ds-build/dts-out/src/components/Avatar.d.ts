import React from "react";
export interface AvatarProps {
    /** Initials or short text shown inside the circle. */
    initials: React.ReactNode;
    size?: number;
    background?: string;
    /** Optional name + role shown to the right. */
    name?: React.ReactNode;
    role?: React.ReactNode;
}
/** Circular initials avatar, optionally with an identity block. */
export declare function Avatar({ initials, size, background, name, role }: AvatarProps): React.JSX.Element;
