# Badge

Small status / label pill.

**Group:** Data Display  ·  **Variants shown:** tones · soft / solid / dot

Available from the design system global as `AdvisoryDS.Badge`.

## Props

| prop | type | notes |
|---|---|---|
| `tone` | `'primary'|'danger'|'warning'|'info'|'success'|'purple'|'neutral'` | color family |
| `variant` | `'soft'|'solid'` | soft tinted (default) or filled |
| `dot` | `boolean` | leading status dot |

## Usage

```jsx
const { Badge } = AdvisoryDS;
```

See `Badge.jsx` for a complete, rendered example.

## Notes

Use solid for counters/NEW; soft for statuses; dot for connection/live indicators.
