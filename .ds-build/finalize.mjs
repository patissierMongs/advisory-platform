// Builds ds-bundle/README.md (conventions header + component index) and the
// _ds_sync.json anchor (content hashes so a future re-sync can skip unchanged).
import { readFileSync, writeFileSync, readdirSync, statSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");
const out = resolve(root, "ds-bundle");
const slug = (g) => g.toLowerCase().replace(/\s+/g, "-");
const sha = (p) => createHash("sha256").update(readFileSync(p)).digest("hex");
const index = JSON.parse(readFileSync(resolve(out, "_preview/_index.json"), "utf8"));

// README
const header = readFileSync(resolve(root, ".design-sync/conventions.md"), "utf8");
const groups = {};
for (const c of index) (groups[c.group] ||= []).push(c);
let idx = "\n\n---\n\n## Components\n\n";
for (const g of Object.keys(groups).sort()) {
  idx += `### ${g}\n\n`;
  for (const c of groups[g].sort((a, b) => a.name.localeCompare(b.name))) {
    idx += `- **${c.name}** — ${c.subtitle} · \`components/${slug(g)}/${c.name}/\`\n`;
  }
  idx += "\n";
}
writeFileSync(resolve(out, "README.md"), header + idx);

// anchor
const sourceKeys = {};
for (const c of index) {
  const dir = resolve(out, "components", slug(c.group), c.name);
  const h = createHash("sha256");
  for (const ext of ["html", "jsx", "d.ts", "prompt.md"]) {
    h.update(readFileSync(resolve(dir, `${c.name}.${ext}`)));
  }
  sourceKeys[c.name] = h.digest("hex").slice(0, 16);
}
const anchor = {
  shape: "offscript",
  source: "web/app.dc.html",
  globalName: "AdvisoryDS",
  generatedAt: process.env.DS_STAMP || null,
  bundleSha12: sha(resolve(out, "_ds_bundle.js")).slice(0, 12),
  styleSha: sha(resolve(out, "styles.css")).slice(0, 12),
  bundleCssSha: sha(resolve(out, "_ds_bundle.css")).slice(0, 12),
  tokensSha: sha(resolve(out, "tokens/tokens.css")).slice(0, 12),
  components: index.map((c) => c.name).sort(),
  sourceKeys,
};
writeFileSync(resolve(out, "_ds_sync.json"), JSON.stringify(anchor, null, 2));
console.log("finalize ok: README + _ds_sync.json (", index.length, "components )");
