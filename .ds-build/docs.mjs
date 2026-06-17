// Distributes emitted .d.ts into each component folder and authors .prompt.md
// usage references for the design agent.
import { readFileSync, writeFileSync, copyFileSync, existsSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const out = resolve(__dirname, "..", "ds-bundle");
const slug = (g) => g.toLowerCase().replace(/\s+/g, "-");
const index = JSON.parse(readFileSync(resolve(out, "_preview/_index.json"), "utf8"));
const byName = Object.fromEntries(index.map((c) => [c.name, c]));

// component name -> { purpose, props:[[name,type,note]], example, notes }
const DOCS = {
  Card: { purpose: "The base white panel surface every section sits on.", props: [["padding", "number|string", "inner padding, default 20"], ["flush", "boolean", "drop border+radius when nesting"]], notes: "Compose freely — put headings, tables, stats inside." },
  Button: { purpose: "Action button in the app's button family.", props: [["variant", "'primary'|'secondary'|'danger'|'warning'|'ghost'|'dark'", "default primary (teal)"], ["size", "'sm'|'md'", "default md"], ["leftIcon", "ReactNode", "optional leading icon"], ["disabled", "boolean", ""]], notes: "primary = teal CTA, dark = navy bulk action, secondary = white outline back/cancel, ghost = teal outline." },
  Badge: { purpose: "Small status / label pill.", props: [["tone", "'primary'|'danger'|'warning'|'info'|'success'|'purple'|'neutral'", "color family"], ["variant", "'soft'|'solid'", "soft tinted (default) or filled"], ["dot", "boolean", "leading status dot"]], notes: "Use solid for counters/NEW; soft for statuses; dot for connection/live indicators." },
  Chip: { purpose: "Removable token (e.g. extracted CVE codes).", props: [["onRemove", "() => void", "shows × button when set"], ["mono", "boolean", "monospace text"]], notes: "" },
  SeverityBadge: { purpose: "CVE severity badge mapping a level to tone + Korean label.", props: [["level", "'critical'|'high'|'medium'|'low'", "required"], ["label", "ReactNode", "override displayed text"]], notes: "critical→red, high→amber, medium→blue, low→neutral. Labels default to 긴급/높음/보통/낮음." },
  StatCard: { purpose: "Metric tile: small label over a large value.", props: [["label", "ReactNode", ""], ["value", "ReactNode", ""], ["unit", "ReactNode", "optional trailing unit"], ["valueColor", "string", "color of the big number"], ["bare", "boolean", "inline, no card chrome — for stat strips"]], notes: "Use bare inside a Card row to build the summary strips." },
  Alert: { purpose: "Inline callout banner.", props: [["tone", "'info'|'warning'|'danger'|'success'", "default info"], ["title", "ReactNode", "bolded lead"], ["action", "ReactNode", "trailing element, usually a Button"], ["children", "ReactNode", "body text"]], notes: "warning/danger get a colored left bar; info/success are mint." },
  DataTable: { purpose: "Grid-based data table for the app's list panels.", props: [["columns", "Column<Row>[]", "{key, header, width?, align?, render?}"], ["data", "Row[]", ""], ["getRowKey", "(row,i)=>Key", "stable keys"], ["bordered", "boolean", "card chrome, default true"]], notes: "Set width to a grid track ('120px' / '1fr'). Use render to drop SeverityBadge/Badge into cells." },
  Sidebar: { purpose: "Dark navy app navigation rail.", props: [["brand", "{icon?, title, subtitle?}", ""], ["items", "NavItemProps[]", "{label, icon?, badge?, active?, onClick?}"], ["footer", "ReactNode", "bottom block"], ["width", "number", "default 248"]], notes: "Pair with Topbar + a light main area. NavItem is also exported for custom rails." },
  Topbar: { purpose: "White app header bar with title + right-aligned actions.", props: [["title", "ReactNode", ""], ["subtitle", "ReactNode", ""], ["actions", "ReactNode", "status pills, Avatar, buttons"]], notes: "Height 60px, sits above the scrolling content area." },
  Stepper: { purpose: "Horizontal numbered step flow with connectors.", props: [["steps", "{label}[]", ""], ["current", "number", "zero-based active index"], ["onStepClick", "(i)=>void", "optional"]], notes: "Steps before current show a check; the connector fills teal up to current." },
  Dropzone: { purpose: "Dashed file-drop area.", props: [["title", "ReactNode", ""], ["hint", "ReactNode", ""], ["buttonLabel", "ReactNode", "pick button, omit to hide"], ["icon", "ReactNode", "default upload arrow"], ["compact", "boolean", "smaller padding"], ["onPick/onDrop/onDragOver", "handlers", ""]], notes: "Wrap in a Card for the standard upload panel." },
  ProgressBar: { purpose: "Thin progress track with optional label row.", props: [["value", "number", "0–100"], ["color", "string", "fill, default teal"], ["label", "ReactNode", ""], ["showValue", "boolean", "show % (default true)"], ["height", "number", "default 7"]], notes: "Use amber/red fills for at-risk progress." },
  Avatar: { purpose: "Circular initials avatar, optionally with identity block.", props: [["initials", "ReactNode", "required"], ["size", "number", "default 32"], ["background", "string", "default teal"], ["name", "ReactNode", ""], ["role", "ReactNode", ""]], notes: "Provide name/role to render the labeled user block used in the Topbar." },
  Modal: { purpose: "Centered overlay dialog (e.g. PDF viewer).", props: [["open", "boolean", "renders nothing when false"], ["onClose", "()=>void", ""], ["title", "ReactNode", ""], ["subtitle", "ReactNode", ""], ["icon", "ReactNode", ""], ["footer", "ReactNode", "right-aligned actions"], ["width", "number", "default 600"]], notes: "Body scrolls; click backdrop or close button to dismiss." },
  Toast: { purpose: "Corner notification with a tone accent bar.", props: [["title", "ReactNode", "required"], ["tone", "'primary'|'danger'|'warning'|'info'|'success'", ""], ["icon", "ReactNode", ""], ["onClose", "()=>void", ""], ["actions", "ReactNode", "confirm/deny row"], ["inline", "boolean", "render in flow instead of fixed bottom-right"]], notes: "Default position is fixed bottom-right; use inline to embed." },
};

function promptMd(name) {
  const c = byName[name];
  const d = DOCS[name];
  const props = d.props.map(([n, t, note]) => `| \`${n}\` | \`${t}\` | ${note || ""} |`).join("\n");
  return `# ${name}

${d.purpose}

**Group:** ${c.group}  ·  **Variants shown:** ${c.subtitle}

Available from the design system global as \`AdvisoryDS.${name}\`.

## Props

| prop | type | notes |
|---|---|---|
${props}

## Usage

\`\`\`jsx
const { ${name} } = AdvisoryDS;
\`\`\`

See \`${name}.jsx\` for a complete, rendered example.

${d.notes ? "## Notes\n\n" + d.notes + "\n" : ""}`;
}

let n = 0;
for (const c of index) {
  const dir = resolve(out, "components", slug(c.group), c.name);
  const dts = resolve(__dirname, "dts-out/src/components", `${c.name}.d.ts`);
  if (existsSync(dts)) copyFileSync(dts, resolve(dir, `${c.name}.d.ts`));
  writeFileSync(resolve(dir, `${c.name}.prompt.md`), promptMd(c.name));
  n++;
}
console.log("docs ok:", n, "components");
