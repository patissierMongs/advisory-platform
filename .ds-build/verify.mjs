// Loads each component's preview card (the SHIPPED bundle + styles) in headless
// Chromium and screenshots it to ds-bundle/_preview/<Name>.png for grading.
import { chromium } from "playwright";
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const out = resolve(__dirname, "..", "ds-bundle");
const slug = (g) => g.toLowerCase().replace(/\s+/g, "-");
const index = JSON.parse(readFileSync(resolve(out, "_preview/_index.json"), "utf8"));

const only = process.argv.slice(2);
const targets = only.length ? index.filter((c) => only.includes(c.name)) : index;

const browser = await chromium.launch();
const errs = [];
for (const c of targets) {
  const page = await browser.newPage({ viewport: { width: Math.round(c.width), height: Math.round(c.height) }, deviceScaleFactor: 2 });
  const consoleErrs = [];
  page.on("pageerror", (e) => consoleErrs.push(String(e)));
  const cardPath = resolve(out, "components", slug(c.group), c.name, `${c.name}.html`);
  await page.goto(pathToFileURL(cardPath).href);
  try {
    await page.evaluate(() => document.fonts && document.fonts.ready);
    await page.waitForFunction(() => document.getElementById("root")?.childElementCount > 0, { timeout: 4000 });
  } catch (e) {
    consoleErrs.push("render-timeout: #root stayed empty");
  }
  await page.waitForTimeout(150);
  await page.screenshot({ path: resolve(out, "_preview", `${c.name}.png`) });
  if (consoleErrs.length) errs.push({ name: c.name, errs: consoleErrs });
  await page.close();
}
await browser.close();

if (errs.length) {
  console.log("RENDER ERRORS:");
  for (const e of errs) console.log(" -", e.name, ":", e.errs.join(" | "));
  process.exit(1);
}
console.log("verify ok:", targets.length, "screenshots →", resolve(out, "_preview"));
