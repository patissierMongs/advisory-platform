# Dropzone

Dashed file-drop area.

**Group:** Forms  ·  **Variants shown:** dashed file-drop area

Available from the design system global as `AdvisoryDS.Dropzone`.

## Props

| prop | type | notes |
|---|---|---|
| `title` | `ReactNode` |  |
| `hint` | `ReactNode` |  |
| `buttonLabel` | `ReactNode` | pick button, omit to hide |
| `icon` | `ReactNode` | default upload arrow |
| `compact` | `boolean` | smaller padding |
| `onPick/onDrop/onDragOver` | `handlers` |  |

## Usage

```jsx
const { Dropzone } = AdvisoryDS;
```

See `Dropzone.jsx` for a complete, rendered example.

## Notes

Wrap in a Card for the standard upload panel.
