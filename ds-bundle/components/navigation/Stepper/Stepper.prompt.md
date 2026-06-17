# Stepper

Horizontal numbered step flow with connectors.

**Group:** Navigation  ·  **Variants shown:** numbered flow with connectors

Available from the design system global as `AdvisoryDS.Stepper`.

## Props

| prop | type | notes |
|---|---|---|
| `steps` | `{label}[]` |  |
| `current` | `number` | zero-based active index |
| `onStepClick` | `(i)=>void` | optional |

## Usage

```jsx
const { Stepper } = AdvisoryDS;
```

See `Stepper.jsx` for a complete, rendered example.

## Notes

Steps before current show a check; the connector fills teal up to current.
