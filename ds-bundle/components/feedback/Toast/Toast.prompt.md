# Toast

Corner notification with a tone accent bar.

**Group:** Feedback  ·  **Variants shown:** corner notification + confirm

Available from the design system global as `AdvisoryDS.Toast`.

## Props

| prop | type | notes |
|---|---|---|
| `title` | `ReactNode` | required |
| `tone` | `'primary'|'danger'|'warning'|'info'|'success'` |  |
| `icon` | `ReactNode` |  |
| `onClose` | `()=>void` |  |
| `actions` | `ReactNode` | confirm/deny row |
| `inline` | `boolean` | render in flow instead of fixed bottom-right |

## Usage

```jsx
const { Toast } = AdvisoryDS;
```

See `Toast.jsx` for a complete, rendered example.

## Notes

Default position is fixed bottom-right; use inline to embed.
