# Modal

Centered overlay dialog (e.g. PDF viewer).

**Group:** Feedback  ·  **Variants shown:** centered overlay dialog

Available from the design system global as `AdvisoryDS.Modal`.

## Props

| prop | type | notes |
|---|---|---|
| `open` | `boolean` | renders nothing when false |
| `onClose` | `()=>void` |  |
| `title` | `ReactNode` |  |
| `subtitle` | `ReactNode` |  |
| `icon` | `ReactNode` |  |
| `footer` | `ReactNode` | right-aligned actions |
| `width` | `number` | default 600 |

## Usage

```jsx
const { Modal } = AdvisoryDS;
```

See `Modal.jsx` for a complete, rendered example.

## Notes

Body scrolls; click backdrop or close button to dismiss.
