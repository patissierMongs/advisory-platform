import React from "react";
export interface Column<Row> {
    key: string;
    header: React.ReactNode;
    /** CSS grid track for this column, e.g. "120px" or "1fr". Default "1fr". */
    width?: string;
    align?: "left" | "center" | "right";
    /** Cell renderer; defaults to row[key]. */
    render?: (row: Row, index: number) => React.ReactNode;
}
export interface DataTableProps<Row> {
    columns: Column<Row>[];
    data: Row[];
    getRowKey?: (row: Row, index: number) => React.Key;
    /** Wrap in a bordered Card surface (default true). */
    bordered?: boolean;
}
/** Grid-based data table matching the app's list/table panels. */
export declare function DataTable<Row extends Record<string, any>>({ columns, data, getRowKey, bordered, }: DataTableProps<Row>): React.JSX.Element;
