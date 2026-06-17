# Button

Action button in the app's button family.

**Group:** Actions  ·  **Variants shown:** primary / dark / danger / secondary / ghost

Available from the design system global as `AdvisoryDS.Button`.

## Props

| prop | type | notes |
|---|---|---|
| `variant` | `'primary'|'secondary'|'danger'|'warning'|'ghost'|'dark'` | default primary (teal) |
| `size` | `'sm'|'md'` | default md |
| `leftIcon` | `ReactNode` | optional leading icon |
| `disabled` | `boolean` |  |

## Usage

```jsx
const { Button } = AdvisoryDS;
```

See `Button.jsx` for a complete, rendered example.

## Notes

primary = teal CTA, dark = navy bulk action, secondary = white outline back/cancel, ghost = teal outline.
