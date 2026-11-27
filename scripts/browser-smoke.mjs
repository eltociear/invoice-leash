// Every published page, opened in a real browser (Playwright): none may throw. Parsing is not enough: a
// function declared twice once made the attack lab throw on its first live read, and every button after
// it did nothing, while every script still parsed. Then the lab's two-click check against the live
// InvoiceDeskV5 (§8), as a judge would press it: the agent's classical key alone is refused
// (BadAgentSignature) and the company in person would pay. Read-only: eth_call only, nothing is sent.
//   node scripts/browser-smoke.mjs            (CI: after npx playwright install chromium)
import { chromium } from "playwright";
import { createServer } from "node:http";
import { existsSync, readFileSync, readdirSync } from "node:fs";

const DOCS = new URL("../docs/", import.meta.url);
const TYPES = { html: "text/html", js: "text/javascript", json: "application/json", css: "text/css", png: "image/png", svg: "image/svg+xml" };
const srv = createServer((q, r) => {
  let p = decodeURIComponent(q.url.split("?")[0].split("#")[0]).replace(/^\/+/, "");
  if (!p || p.endsWith("/")) p += "index.html";
  const f = new URL(p, DOCS);
  if (p.includes("..") || !existsSync(f)) { r.writeHead(404); return r.end(); }
  r.writeHead(200, { "content-type": TYPES[p.split(".").pop()] ?? "application/octet-stream" }); r.end(readFileSync(f));
});
await new Promise((ok) => srv.listen(0, "127.0.0.1", ok));
const base = `http://127.0.0.1:${srv.address().port}/`;

// Playwright's own browser, else any headless shell it has downloaded before (a local run)
function browserPath() {
  const dir = `${process.env.HOME}/Library/Caches/ms-playwright/`;
  if (!existsSync(dir)) return undefined;
  for (const d of readdirSync(dir).filter((x) => x.startsWith("chromium_headless_shell-")).sort().reverse())
    for (const sub of readdirSync(dir + d)) { const p = `${dir}${d}/${sub}/chrome-headless-shell`; if (existsSync(p)) return p; }
}
let b;
try { b = await chromium.launch(); } catch { b = await chromium.launch({ executablePath: browserPath() }); }
const bad = [];
let n = 0;
for (const f of readdirSync(DOCS).filter((f) => f.endsWith(".html"))) {
  const p = await b.newPage();
  const errs = [];
  p.on("pageerror", (e) => errs.push(e.message));
  await p.goto(base + f, { waitUntil: "load" });
  await p.waitForTimeout(3000); // the pages' first reads of the chain start on load
  if (errs.length) bad.push(`docs/${f}: ${errs.join("; ")}`); else n++;
  await p.close();
}
// the lab's §8, against the live desk; a public testnet flakes, so each answer gets three tries
const p = await b.newPage();
const errs = [];
p.on("pageerror", (e) => errs.push(e.message));
await p.goto(base + "lab.html#v5", { waitUntil: "load" });
const answer = async (btn) => {
  for (let k = 0; k < 3; k++) {
    const before = await p.textContent("#v5out");
    await p.click(btn);
    await p.waitForFunction((b) => document.getElementById("v5out").textContent !== b, before, { timeout: 60000 });
    const line = (await p.innerHTML("#v5out")).split("<br>").pop().replace(/<[^>]+>/g, "");
    if (/BadAgentSignature|AgentSignatureExpired|WOULD PAY/.test(line)) return line;
    await p.waitForTimeout(5000);
  }
  return (await p.textContent("#v5out")).slice(-200);
};
const agent = await answer("#v5-none"), company = await answer("#v5-company");
if (!/: BadAgentSignature$/.test(agent)) bad.push(`lab §8, the agent's classical key alone: ${agent}`);
if (!/: WOULD PAY$/.test(company)) bad.push(`lab §8, the company in person: ${company}`);
if (errs.length) bad.push(`lab §8: ${errs.join("; ")}`);
await b.close(); srv.close();
if (bad.length) { console.log(bad.map((x) => "✗ " + x).join("\n")); process.exit(1); }
console.log(`✓ browser: ${n} pages open without an error; the lab's §8 asks the live InvoiceDeskV5: the agent's classical key alone, BadAgentSignature; the company, WOULD PAY`);
