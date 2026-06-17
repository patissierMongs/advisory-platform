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
export function DataTable<Row extends Record<string, any>>({
  columns,
  data,
  getRowKey,
  bordered = true,
}: DataTableProps<Row>) {
  const template = columns.map((c) => c.width ?? "1fr").join(" ");
  const cell = (c: Column<Row>): React.CSSProperties => ({
    textAlign: c.align ?? "left",
    justifyContent: c.align === "center" ? "center" : c.align === "right" ? "flex-end" : "flex-start",
  });

  return (
    <div
      style={{
        background: "var(--ds-color-surface)",
        border: bordered ? "1px solid var(--ds-color-border)" : "none",
        borderRadius: bordered ? "var(--ds-radius-xl)" : 0,
        overflow: "hidden",
      }}
    >
      <div
        style={{
          display: "grid",
          gridTemplateColumns: template,
          padding: "10px 20px",
          background: "var(--ds-color-surface-subtle)",
          borderBottom: "1px solid var(--ds-color-border-soft)",
          fontSize: 11,
          fontWeight: 700,
          color: "var(--ds-color-text-faint)",
        }}
      >
        {columns.map((c) => (
          <span key={c.key} style={cell(c)}>{c.header}</span>
        ))}
      </div>
      {data.map((row, i) => (
        <div
          key={getRowKey ? getRowKey(row, i) : i}
          className="ads-row"
          style={{
            display: "grid",
            gridTemplateColumns: template,
            alignItems: "center",
            padding: "11px 20px",
            borderBottom: i === data.length - 1 ? "none" : "1px solid var(--ds-color-border-faint)",
            fontSize: 12.5,
            color: "var(--ds-color-text-body)",
          }}
        >
          {columns.map((c) => (
            <span key={c.key} style={{ display: "flex", ...cell(c) }}>
              {c.render ? c.render(row, i) : row[c.key]}
            </span>
          ))}
        </div>
      ))}
    </div>
  );
}
