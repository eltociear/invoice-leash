// The Desk Console (docs/app.html), driven in a real browser against your own desk through `desk.mjs serve`.
// Every step is a real testnet transaction made by the local signer; the page only asks for it.
//
//   LEASH_HOME=<your desk> LEASH_SERVE_TOKEN=<token> node desk.mjs serve 8742     (in one terminal)
//   CONSOLE_TOKEN=<token> node scripts/console-e2e.mjs [steps] [out.json]
// steps, comma-separated, in order (default: rotate,triage,run,export):
//   rotate   "New agent signer": a fresh ML-DSA-87 signer named in the desk; every signature the old one made is void
//   triage   sort the inbox                 run      the agent pays what triage allows
//   export   the accounting CSV, read from the chain
//   approve-public, sign, forge             the public-test-vendor steps (only on a desk you use to try the console)
// The pages are served from docs/ on 127.0.0.1:8765 (an origin desk.mjs serve allows).
import { chromium } from "playwright";
import { createServer } from "node:http";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";

const ROOT = new URL("../", import.meta.url);
const TOKEN = process.env.CONSOLE_TOKEN ?? process.env.LEASH_SERVE_TOKEN, SIGNER = process.env.CONSOLE_SIGNER ?? "http://127.0.0.1:8742";
if (!TOKEN) throw new Error("set CONSOLE_TOKEN to the token desk.mjs serve uses (LEASH_SERVE_TOKEN)");
const steps = (process.argv[2] ?? "rotate,triage,run,export").split(","), OUT = process.argv[3];

// a browser: Playwright's own, else any Chromium it has downloaded
function browserPath() {
  const dir = `${process.env.HOME}/Library/Caches/ms-playwright/`;
  if (!existsSync(dir)) return undefined;
  for (const d of readdirSync(dir).filter((x) => x.startsWith("chromium_headless_shell-")).sort().reverse()) {
    for (const sub of readdirSync(dir + d)) { const p = `${dir}${d}/${sub}/chrome-headless-shell`; if (existsSync(p)) return p; }
  }
}
const srv = createServer((q, r) => {
  const p = new URL(`docs${q.url.split("?")[0].split("#")[0]}`, ROOT);
  if (!existsSync(p)) { r.writeHead(404); return r.end(); }
  r.writeHead(200, { "content-type": p.pathname.endsWith(".html") ? "text/html" : p.pathname.endsWith(".js") ? "text/javascript" : "application/json" });
  r.end(readFileSync(p));
}).listen(8765, "127.0.0.1");
let b;
try { b = await chromium.launch(); } catch { b = await chromium.launch({ executablePath: browserPath() }); }
const p = await b.newPage({ viewport: { width: 1280, height: 2400 } });
const errs = []; p.on("pageerror", (e) => errs.push(e.message));
await p.goto(`http://127.0.0.1:8765/app.html#local=${SIGNER}&token=${TOKEN}`);
const text = async (id) => (await p.textContent(`#${id}`)).replace(/\s+/g, " ").trim();
const until = async (id, re, ms = 300000) => { await p.waitForFunction(([id, re]) => new RegExp(re).test(document.getElementById(id).textContent), [id, re], { timeout: ms }); return text(id); };
const record = { what: "the Desk Console driven in a real browser (Playwright) against desk.mjs serve", at: new Date().toISOString(), steps: [] };
record.statusBefore = (await until("lstat", "InvoiceDeskV")).slice(0, 400);
// one button, one testnet action; a network failure is reported by the page and the step is repeated
// (safe: the signer asks the chain first, so nothing is done twice)
async function act(btn, title) {
  for (let k = 0; k < 4; k++) {
    const before = await p.textContent("#llog");
    await p.click(btn);
    await p.waitForFunction(([t, b]) => { const x = document.getElementById("llog").textContent, first = x.split("\n")[0]; return x !== b && first.includes(t + ": ") && !/: working/.test(first); }, [title, before], { timeout: 300000 });
    const t = await text("llog");
    if (t.slice(0, 200).includes(`${title}: done`)) return t.slice(0, 1200);
    if (!/could not reach|cannot reach/.test(t.slice(0, 400))) throw new Error(`step failed: ${t.slice(0, 300)}`);
  }
  throw new Error("the network kept failing");
}
for (const s of steps) {
  let out;
  if (s === "rotate") out = await act("#a-rotate", "new agent signer (every signature the old one made is void)");
  if (s === "approve-public") out = await act("#v-pub", "approve the public test vendor");
  if (s === "sign") out = await act("#i-sign", "signed in this tab)");
  if (s === "forge") out = await act("#i-forge", "(forged)");
  if (s === "triage") { await p.click("#i-triage"); out = await until("tri", "AGENT PAYS|NEEDS|REJECTED|ALREADY PAID|empty"); }
  if (s === "run") { out = await act("#i-run", "the agent pays what triage allows"); await p.waitForTimeout(3000); }
  if (s === "export") { await p.click("#x-export"); out = await until("xout", "paid_at_utc"); }
  if (out === undefined) throw new Error(`unknown step ${s}`);
  console.log(`${s}:`, out.slice(0, 300));
  record.steps.push({ step: s, page: out.slice(0, 1500) });
}
record.statusAfter = (await text("lstat")).slice(0, 400);
record.pageErrors = errs;
console.log("page errors:", errs.length);
if (OUT) writeFileSync(OUT, JSON.stringify(record, null, 1) + "\n");
await b.close(); srv.close();
if (errs.length) process.exitCode = 1;
