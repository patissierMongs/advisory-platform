# ProgressBar

Thin progress track with optional label row.

**Group:** Data Display  ·  **Variants shown:** per-department progress

Available from the design system global as `AdvisoryDS.ProgressBar`.

## Props

| prop | type | notes |
|---|---|---|
| `value` | `number` | 0–100 |
| `color` | `string` | fill, default teal |
| `label` | `ReactNode` |  |
| `showValue` | `boolean` | show % (default true) |
| `height` | `number` | default 7 |

## Usage

```jsx
const { ProgressBar } = AdvisoryDS;
```

See `ProgressBar.jsx` for a complete, rendered example.

## Notes

Use amber/red fills for at-risk progress.
