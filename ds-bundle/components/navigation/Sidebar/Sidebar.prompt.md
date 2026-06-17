# Sidebar

Dark navy app navigation rail.

**Group:** Navigation  ·  **Variants shown:** nav rail with brand + items

Available from the design system global as `AdvisoryDS.Sidebar`.

## Props

| prop | type | notes |
|---|---|---|
| `brand` | `{icon?, title, subtitle?}` |  |
| `items` | `NavItemProps[]` | {label, icon?, badge?, active?, onClick?} |
| `footer` | `ReactNode` | bottom block |
| `width` | `number` | default 248 |

## Usage

```jsx
const { Sidebar } = AdvisoryDS;
```

See `Sidebar.jsx` for a complete, rendered example.

## Notes

Pair with Topbar + a light main area. NavItem is also exported for custom rails.
