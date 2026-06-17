# Avatar

Circular initials avatar, optionally with identity block.

**Group:** Data Display  ·  **Variants shown:** initials circle + identity

Available from the design system global as `AdvisoryDS.Avatar`.

## Props

| prop | type | notes |
|---|---|---|
| `initials` | `ReactNode` | required |
| `size` | `number` | default 32 |
| `background` | `string` | default teal |
| `name` | `ReactNode` |  |
| `role` | `ReactNode` |  |

## Usage

```jsx
const { Avatar } = AdvisoryDS;
```

See `Avatar.jsx` for a complete, rendered example.

## Notes

Provide name/role to render the labeled user block used in the Topbar.
