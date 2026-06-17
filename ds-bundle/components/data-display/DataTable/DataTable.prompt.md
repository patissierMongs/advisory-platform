# DataTable

Grid-based data table for the app's list panels.

**Group:** Data Display  ·  **Variants shown:** grid table with badges

Available from the design system global as `AdvisoryDS.DataTable`.

## Props

| prop | type | notes |
|---|---|---|
| `columns` | `Column<Row>[]` | {key, header, width?, align?, render?} |
| `data` | `Row[]` |  |
| `getRowKey` | `(row,i)=>Key` | stable keys |
| `bordered` | `boolean` | card chrome, default true |

## Usage

```jsx
const { DataTable } = AdvisoryDS;
```

See `DataTable.jsx` for a complete, rendered example.

## Notes

Set width to a grid track ('120px' / '1fr'). Use render to drop SeverityBadge/Badge into cells.
