# Advisory Platform DS — how to build with it

A compact React kit extracted from a Korean security-advisory workflow app
(CVE intake → asset matching → departmental dispatch). Surfaces are calm and
dense: white cards on a `#eef1f5` canvas, a teal (`#0f766e`) accent, a dark navy
(`#0f2742`) nav rail, and the **Pretendard** typeface.

## Setup — what must be loaded

Components are compiled into a global: `window.AdvisoryDS.<Name>` (React 18 is
expected on `window.React`). They are **self-styling** — each renders inline
styles that reference CSS variables. Those variables, the Pretendard font, and
the interaction CSS all live behind **`styles.css`**, so a screen renders
correctly only when `styles.css` is loaded. There is **no provider/context** to
mount. Wrap your app content in an element with `className="ads-root"` so font
and scrollbar styling inherit (use `ads-scroll` on scroll containers).

```jsx
const { Sidebar, Topbar, Card, DataTable } = AdvisoryDS;
// <link rel="stylesheet" href="styles.css"> must be present
```

## Styling idiom — tokens, not utility classes

There is **no class-name utility system**. Style your own layout glue with inline
styles that reference the DS token variables (exactly how the source app is
built). Always prefer a token over a raw hex/px value:

| family | real variable names |
|---|---|
| brand teal | `--ds-color-primary` `--ds-color-primary-strong` `--ds-color-primary-tint` `--ds-color-primary-border` `--ds-color-primary-accent` |
| navy / ink | `--ds-color-navy` `--ds-color-navy-deep` |
| canvas / surfaces | `--ds-color-bg` `--ds-color-surface` `--ds-color-surface-subtle` `--ds-color-surface-muted` `--ds-color-surface-alt` |
| borders | `--ds-color-border` `--ds-color-border-soft` `--ds-color-border-faint` `--ds-color-border-field` |
| text ramp | `--ds-color-text` `--ds-color-text-strong` `--ds-color-text-body` `--ds-color-text-muted` `--ds-color-text-soft` `--ds-color-text-faint` |
| semantic | `--ds-color-danger(-text/-tint/-border)` `--ds-color-warning(-strong/-text/-tint/-border/-accent)` `--ds-color-info(-tint/-border)` `--ds-color-success(-tint/-border)` `--ds-color-purple(-tint/-border)` |
| radius | `--ds-radius-sm` `--ds-radius-md` `--ds-radius-lg` `--ds-radius-xl` `--ds-radius-2xl` |
| spacing | `--ds-space-1`…`--ds-space-7` |
| type | `--ds-font-family` `--ds-font-mono` `--ds-font-size-xs…xl` `--ds-font-weight-medium/bold/black` |

CVE codes, IPs and timestamps are rendered in `--ds-font-mono`.

## Where the truth lives

- **`styles.css`** and its `@import` closure: `tokens/tokens.css` (every variable
  above), `fonts/pretendard.css`, `_ds_bundle.css` (focus/hover/scrollbar/toast
  animation). Read these before inventing any value.
- **`components/<group>/<Name>/`** — each has `<Name>.d.ts` (the prop contract,
  `<Name>Props`), `<Name>.prompt.md` (usage + variants), and `<Name>.jsx` (a
  real rendered example you can copy).

## One idiomatic screen

```jsx
const { Sidebar, Topbar, Card, DataTable, SeverityBadge, Badge } = AdvisoryDS;

<div className="ads-root" style={{ display: "flex", height: "100vh" }}>
  <Sidebar
    brand={{ title: "보안권고문 처리", subtitle: "취약점 대응 워크플로우" }}
    items={[{ label: "권고문 처리", active: true, badge: "3" }, { label: "CVE 데이터베이스" }]}
  />
  <main style={{ flex: 1, background: "var(--ds-color-bg)" }} className="ads-scroll">
    <Topbar title="권고문 처리" subtitle="CVE 추출 · 조회" />
    <div style={{ padding: 24 }}>
      <Card padding={0}>
        <DataTable
          columns={[
            { key: "id", header: "CVE", width: "160px",
              render: (r) => <span style={{ fontFamily: "var(--ds-font-mono)", color: "var(--ds-color-primary-strong)" }}>{r.id}</span> },
            { key: "product", header: "제품 / OS", width: "1fr" },
            { key: "sev", header: "심각도", width: "90px", align: "center",
              render: (r) => <SeverityBadge level={r.sev} /> },
          ]}
          data={rows}
          getRowKey={(r) => r.id}
        />
      </Card>
    </div>
  </main>
</div>
```
