# Alert

Inline callout banner.

**Group:** Feedback  ·  **Variants shown:** info / success / warning / danger

Available from the design system global as `AdvisoryDS.Alert`.

## Props

| prop | type | notes |
|---|---|---|
| `tone` | `'info'|'warning'|'danger'|'success'` | default info |
| `title` | `ReactNode` | bolded lead |
| `action` | `ReactNode` | trailing element, usually a Button |
| `children` | `ReactNode` | body text |

## Usage

```jsx
const { Alert } = AdvisoryDS;
```

See `Alert.jsx` for a complete, rendered example.

## Notes

warning/danger get a colored left bar; info/success are mint.
