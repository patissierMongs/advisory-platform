# StatCard

Metric tile: small label over a large value.

**Group:** Data Display  ·  **Variants shown:** metric tiles

Available from the design system global as `AdvisoryDS.StatCard`.

## Props

| prop | type | notes |
|---|---|---|
| `label` | `ReactNode` |  |
| `value` | `ReactNode` |  |
| `unit` | `ReactNode` | optional trailing unit |
| `valueColor` | `string` | color of the big number |
| `bare` | `boolean` | inline, no card chrome — for stat strips |

## Usage

```jsx
const { StatCard } = AdvisoryDS;
```

See `StatCard.jsx` for a complete, rendered example.

## Notes

Use bare inside a Card row to build the summary strips.
