# SeverityBadge

CVE severity badge mapping a level to tone + Korean label.

**Group:** Data Display  ·  **Variants shown:** critical / high / medium / low

Available from the design system global as `AdvisoryDS.SeverityBadge`.

## Props

| prop | type | notes |
|---|---|---|
| `level` | `'critical'|'high'|'medium'|'low'` | required |
| `label` | `ReactNode` | override displayed text |

## Usage

```jsx
const { SeverityBadge } = AdvisoryDS;
```

See `SeverityBadge.jsx` for a complete, rendered example.

## Notes

critical→red, high→amber, medium→blue, low→neutral. Labels default to 긴급/높음/보통/낮음.
