# Advisory Platform DS — sync notes

- **Source is not a design-system repo.** It's a single hand-built screen
  (`web/app.dc.html`) using the in-house `dc-runtime` template DSL, all styling
  inline, no compiled component library. There is no `dc-runtime/src` in this
  repo (only the generated `web/support.js`). The components in this DS were
  **authored from the screen's recurring patterns** — they are a faithful
  extraction, not a 1:1 export of existing component source.
- **Build pipeline** (run from repo root): `.ds-build/build.mjs` (esbuild bundle
  + assets) → `gen.mjs` (preview cards + .jsx + preview runtime) → `verify.mjs`
  (headless screenshots) → `docs.mjs` (.d.ts via tsc + .prompt.md) →
  `finalize.mjs` (README + `_ds_sync.json`).
- **React** is consumed from `window.React` (shim at `.ds-build/react-shim.js`);
  React 18 is vendored into `_vendor/` so preview cards render standalone.
- **Verification** is screenshot-based (Playwright chromium) since there's no
  Storybook to diff against — graded on the absolute rubric. All 16 passed on
  the first build.
- Minor cosmetic: Sidebar card shows canvas padding to the right of the 248px
  rail; Stepper label can wrap at narrow widths. Acceptable for cards.
