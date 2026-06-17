// Generates, from previews/*.jsx: the preview runtime bundle, per-component
// preview cards (self-contained, render the SHIPPED bundle), readable .jsx
// artifacts, and headless screenshots for verification.
import * as esbuild from "esbuild";
import { readdirSync, readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { dirname, resolve, basename } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");
const out = resolve(root, "ds-bundle");
const prevDir = resolve(__dirname, "previews");
const ensure = (p) => mkdirSync(p, { recursive: true });

const slug = (g) => g.toLowerCase().replace(/\s+/g, "-");
const lit = (txt, key) => {
  const m = new RegExp(key + '\\s*:\\s*("([^"]*)"|(\\d+(?:\\.\\d+)?))').exec(txt);
  return m ? (m[2] !== undefined ? m[2] : Number(m[3])) : undefined;
};

// 1) discover previews + meta
const files = readdirSync(prevDir).filter((f) => f.endsWith(".jsx"));
const comps = files.map((f) => {
  const name = basename(f, ".jsx");
  const txt = readFileSync(resolve(prevDir, f), "utf8");
  return {
    name,
    file: f,
    group: lit(txt, "group") || "Components",
    width: lit(txt, "width") || 600,
    height: lit(txt, "height") || 300,
    subtitle: lit(txt, "subtitle") || "",
    src: txt,
  };
});
comps.sort((a, b) => a.name.localeCompare(b.name));

// 2) generate + bundle the preview runtime
const reg = `import React from "react";
${comps.map((c) => `import P_${c.name} from "./${c.file}";`).join("\n")}
const REG = { ${comps.map((c) => `${c.name}: P_${c.name}`).join(", ")} };
function render(name, elId) {
  const el = document.getElementById(elId);
  const node = React.createElement(REG[name]);
  const RD = window.ReactDOM;
  if (RD.createRoot) RD.createRoot(el).render(node); else RD.render(node, el);
}
globalThis.AdvisoryPreviews = { render, list: () => Object.keys(REG) };
`;
const regPath = resolve(prevDir, "_runtime.generated.jsx");
writeFileSync(regPath, reg);

ensure(resolve(out, "_preview"));
await esbuild.build({
  entryPoints: [regPath],
  bundle: true,
  format: "iife",
  outfile: resolve(out, "_preview/_previews.js"),
  jsx: "transform",
  jsxFactory: "React.createElement",
  jsxFragment: "React.Fragment",
  alias: { react: resolve(__dirname, "react-shim.js") },
  legalComments: "none",
});
rmSync(regPath);

// 3) per-component card HTML + readable .jsx
function cardHtml(c) {
  return `<!-- @dsCard group="${c.group}" name="${c.name}" -->
<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${c.name} — Advisory Platform DS</title>
<link rel="stylesheet" href="../../../styles.css">
<style>html,body{margin:0}#root{min-height:100vh}</style>
</head>
<body>
<div id="root" class="ads-scroll"></div>
<script src="../../../_vendor/react.production.min.js"></script>
<script src="../../../_vendor/react-dom.production.min.js"></script>
<script src="../../../_ds_bundle.js"></script>
<script src="../../../_preview/_previews.js"></script>
<script>AdvisoryPreviews.render(${JSON.stringify(c.name)}, "root");</script>
</body>
</html>
`;
}
function readableJsx(c) {
  // rewrite preview imports into a realistic usage example
  return c.src
    .replace(/import React from "react";\n/, "")
    .replace(/from "\.\/ds"/, 'from "advisory-platform-ds"')
    .replace(/export const meta = .*\n/, "");
}

for (const c of comps) {
  const dir = resolve(out, "components", slug(c.group), c.name);
  ensure(dir);
  writeFileSync(resolve(dir, `${c.name}.html`), cardHtml(c));
  writeFileSync(resolve(dir, `${c.name}.jsx`), readableJsx(c));
}

writeFileSync(resolve(out, "_preview", "_index.json"), JSON.stringify(comps.map(({ src, ...m }) => m), null, 2));
console.log("gen ok:", comps.length, "components");
