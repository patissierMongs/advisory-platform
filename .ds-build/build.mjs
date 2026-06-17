// Off-script converter for the Advisory Platform DS.
// Bundles src/ TSX into ds-bundle/_ds_bundle.js (window.AdvisoryDS.*) and
// copies the static style/token/font assets into the upload layout.
import * as esbuild from "esbuild";
import { mkdirSync, copyFileSync, rmSync, existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");
const out = resolve(root, "ds-bundle");

function ensure(p) { mkdirSync(p, { recursive: true }); }
function cp(from, to) { ensure(dirname(to)); copyFileSync(from, to); }

// fresh component/preview trees are managed elsewhere; only clean the build-owned base files
ensure(out);

// 1) JS bundle
await esbuild.build({
  entryPoints: [resolve(__dirname, "src/index.ts")],
  bundle: true,
  format: "iife",
  globalName: "AdvisoryDS",
  outfile: resolve(out, "_ds_bundle.js"),
  jsx: "transform",
  jsxFactory: "React.createElement",
  jsxFragment: "React.Fragment",
  alias: { react: resolve(__dirname, "react-shim.js") },
  banner: { js: "// @ds-bundle AdvisoryDS — generated from web/app.dc.html patterns. Do not edit by hand." },
  minify: false,
  target: "es2019",
  legalComments: "none",
});

// 2) static assets → upload layout
const A = resolve(__dirname, "assets");
cp(resolve(A, "tokens.css"), resolve(out, "tokens/tokens.css"));
cp(resolve(A, "components.css"), resolve(out, "_ds_bundle.css"));
cp(resolve(A, "styles.css"), resolve(out, "styles.css"));
cp(resolve(A, "pretendard.css"), resolve(out, "fonts/pretendard.css"));
cp(resolve(root, "web/vendor/PretendardVariable.woff2"), resolve(out, "fonts/PretendardVariable.woff2"));

// 3) vendored React (so preview cards render self-contained)
cp(resolve(root, "web/vendor/react.production.min.js"), resolve(out, "_vendor/react.production.min.js"));
cp(resolve(root, "web/vendor/react-dom.production.min.js"), resolve(out, "_vendor/react-dom.production.min.js"));

console.log("build ok →", out);
