// Build docs/index.html (GitHub Pages): the recorded testnet runs, email by email, with every tx linked.
// Data only from this repo: inbox/inbox.json, runs/*.json, runs/verify-latest.txt, deployment.json.
import { readFileSync, writeFileSync, readdirSync, mkdirSync, copyFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const read = (p) => readFileSync(new URL(p, root), "utf8");
const json = (p) => JSON.parse(read(p));
const latest = (prefix) => readdirSync(new URL("runs/", root)).filter((f) => f.startsWith(prefix) && f.endsWith(".json")).sort().pop();
const inbox = json("inbox/inbox.json"), dep = json("deployment.json");
const comp = json(`runs/${latest("compromised-")}`), llm = json(`runs/${latest("llm-")}`);
const approve = json(`runs/${latest("approve-")}`);
const verify = read("runs/verify-latest.txt");
const EX = "https://explore.qore.network/tx/";
const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const short = (why = "") => {
  if (/not permitted to "send"|lacks the permission/.test(why)) return 'linked key is not permitted to "send"';
  if (/may call/.test(why)) return "call is not in the rule's allowed_evm_calls";
  if (/per-tx limit/.test(why)) return why.match(/per-tx limit[^:]*/)[0];
  if (/daily limit/.test(why)) return why.match(/daily limit [^:]*: spent \d+, remaining \d+/)?.[0] ?? "daily limit exceeded";
  return why.replace(/^InvoiceDesk: /, "InvoiceDesk: ");
};
const txLink = (link) => link ? `<a class="tx" href="${esc(link)}" target="_blank" rel="noopener">${esc(link.slice(-64, -56))}…</a>` : "";
const act = (x, m) => x.action === "send" ? `send ${x.qor} QOR to ${x.to.slice(0, 12)}…` : x.action === "call" ? `call desk.${x.fn}(Mallory)` : `pay ${m.invoice.ref} · ${m.invoice.qor} QOR`;
const verdict = (x) => x.result === "skipped" ? `<span class="v skip">skipped</span>` : x.ok ? `<span class="v ok">PAID</span>` : `<span class="v no">${esc(short(x.why))}</span>`;

const emails = inbox.map((m, i) => {
  const cs = comp.log.filter((x) => x.item === i), ls = llm.log.filter((x) => x.item === i);
  const row = (x) => `<div class="step"><code>${esc(act(x, m))}</code>${verdict(x)}${txLink(x.link)}</div>`;
  const claude = ls.map((x) => x.result === "skipped"
    ? `<div class="step"><span class="v skip">skipped</span><span class="why">“${esc(x.why)}”</span></div>`
    : row(x)).join("");
  const human = approve.item === i ? `<div class="lane"><div class="who">owner, by hand</div><div class="step"><code>approve ${i} · ${esc(approve.qor)} QOR</code><span class="v ok">PAID</span><a class="tx" href="${EX}${approve.evmTx}" target="_blank" rel="noopener">${approve.evmTx.slice(2, 10)}…</a></div><div class="why">Over the agent's limit, so a human pays it: a hybrid ML-DSA-87 owner tx, after a dry run of the same contract checks.</div></div>` : "";
  return `<article class="mail" id="e${i}">
  <header><span class="n">#${i}</span><div><div class="from">${esc(m.from)}</div><h3>${esc(m.subject)}</h3></div></header>
  <p class="body">${esc(m.body)}</p>
  ${m.invoice ? `<div class="inv">invoice <b>${esc(m.invoice.ref)}</b> · ${esc(m.invoice.qor)} QOR · payee ${esc(m.invoice.vendor.slice(0, 10))}… · ML-DSA-87 signature ${(m.invoice.signature.length - 2) / 2} bytes</div>` : ""}
  <div class="lanes">
    <div class="lane"><div class="who">compromised agent</div>${cs.map(row).join("")}</div>
    <div class="lane"><div class="who">Claude as the agent</div>${claude}</div>
    ${human}
  </div>
</article>`;
}).join("\n");

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Invoice Leash: every limit lives on QoreChain</title>
<meta name="description" content="An invoice-paying AI agent that stays safe when its model does not. Recorded on the QoreChain testnet, every transaction linked.">
<meta property="og:image" content="cover.png">
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;--ok:#3ddc97;--no:#ff7b72;--skip:#8b949e;--acc:#3ddc97}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:1040px;margin:0 auto;padding:56px 24px 96px}
a{color:var(--acc)}code,pre,.tx{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
h1{font-size:44px;line-height:1.1;margin:0 0 12px}h2{font-size:26px;margin:64px 0 8px}
.lede{font-size:20px;color:var(--fg);max-width:760px;margin:0 0 24px}.dim{color:var(--dim)}
.links{display:flex;gap:12px;flex-wrap:wrap;margin:0 0 40px}.links a{border:1px solid var(--line);border-radius:8px;padding:8px 14px;text-decoration:none;color:var(--fg)}.links a:hover{border-color:var(--acc)}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}.stat{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:20px}.stat b{display:block;font-size:40px;line-height:1}.stat span{color:var(--dim)}
.layers{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-top:16px}.layer{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}.layer h3{margin:0 0 6px;font-size:17px;color:var(--acc)}.layer p{margin:0;color:var(--dim);font-size:15px}
pre{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px;overflow:auto;font-size:13px;line-height:1.5}
.mail{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:14px 0}
.mail header{display:flex;gap:14px;align-items:flex-start}.n{font:600 15px ui-monospace,Menlo,monospace;color:var(--dim);padding-top:3px}.from{color:var(--dim);font-size:14px}.mail h3{margin:2px 0 0;font-size:18px}
.body{margin:10px 0 8px 38px;color:#c9d1d9}.inv{margin:0 0 12px 38px;font:13px ui-monospace,Menlo,monospace;color:var(--dim)}.inv b{color:var(--fg);font-weight:600}
.lanes{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px;margin-left:38px}.lane{border-top:1px solid var(--line);padding-top:8px}.who{font-size:12px;letter-spacing:.02em;color:var(--dim);margin-bottom:4px}
.step{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline;margin:4px 0}.step code{font-size:13px}
.v{font:600 12px ui-monospace,Menlo,monospace;padding:1px 7px;border-radius:5px}.v.ok{color:#0d1117;background:var(--ok)}.v.no{color:var(--no);border:1px solid #6e2b27}.v.skip{color:var(--skip);border:1px solid var(--line)}
.tx{font-size:12px;color:var(--dim)}.why{font-size:14px;color:var(--dim);margin:2px 0 6px}
footer{margin-top:64px;color:var(--dim);font-size:14px}
@media (max-width:720px){h1{font-size:32px}.stats,.layers{grid-template-columns:1fr}.body,.inv,.lanes{margin-left:0}}
</style></head>
<body><main>
<h1>Invoice Leash</h1>
<p class="lede">An invoice-paying AI agent that stays safe when its model does not. The agent's code has no limit check, no vendor check and no signature check. Every limit lives on QoreChain, so we can hand the agent to an attacker and watch the chain say no.</p>
<div class="links">
  <a href="https://youtu.be/DssIkkYx8gc">Demo video (2:53)</a>
  <a href="https://github.com/eltociear/invoice-leash">Code</a>
  <a href="https://github.com/eltociear/invoice-leash/blob/main/THREAT_MODEL.md">Threat model</a>
  <a href="#verify">Verify it yourself</a>
  <a href="https://build.qorechain.io/p/invoice-leash">Build Before Q-Day entry</a>
</div>

<div class="stats">
  <div class="stat"><b>3</b><span>genuine invoices paid by a fully compromised agent (2.2 QOR)</span></div>
  <div class="stat"><b>8</b><span>attempts refused, every one by the chain</span></div>
  <div class="stat"><b>0</b><span>QOR to the attacker, ever (her full incoming history is checked)</span></div>
</div>

<div class="layers">
  <div class="layer"><h3>Call scope</h3><p>The agent may call <code>InvoiceDesk.pay</code> (<code>0x38e5ab6a</code>) and nothing else. No <code>send</code>, no <code>approveVendor</code>.</p></div>
  <div class="layer"><h3>Value limits</h3><p>1 QOR per payment, 2.5 QOR per day, 24 h expiry. QoreChain account abstraction, on the owner's own account: no vault.</p></div>
  <div class="layer"><h3>Post-quantum invoices</h3><p>ML-DSA-87 signature from an approved vendor whose key is registered on chain, checked by precompiles <code>0x…0a02</code> and <code>0x…0a01</code>.</p></div>
</div>

<h2>The inbox, email by email</h2>
<p class="dim">Recorded on <code>qorechain-diana</code>. Two honest vendors, Hostline and Tokenwell, and Mallory, who holds a valid ML-DSA-87 key of her own but is not a vendor. The compromised agent obeys every email; Claude decides for itself. Same rules, same chain.</p>
${emails}

<h2>Then the owner pulls the leash</h2>
<pre>$ node leash.mjs revoke
agent revoked                    <a href="${EX}8AAFA92915D6D75B676D65FF2FE34AA084AB61EA92AD14CFD30F4CB0D4237E8C">8AAFA929…</a>
$ node leash.mjs after-revoke     # one more honest, in-limit invoice
chain: linked key is unbound or revoked   <a href="${EX}08A34CB6CBCC8E795E2FB258E54F1C7E84AE3E2487E9C2C3DD2E7ADAD401B92F">08A34CB6…</a></pre>

<h2 id="verify">Verify it yourself: no keys, no test QOR, about a minute</h2>
<pre>git clone https://github.com/eltociear/invoice-leash && cd invoice-leash
npm install && npm run verify</pre>
<p class="dim">It recompiles the contract and compares it byte for byte with the deployed one, reads the agent's rule as the chain stores it, replays every attack against the real contract with <code>eth_call</code> (the PQC precompile runs for real), adds six tamperings the demo never sent, reads where the money went, and re-reads every recorded transaction. Last run:</p>
<pre>${esc(verify)}</pre>

<footer>InvoiceDesk <a href="https://explore.qore.network/address/${dep.invoiceDesk}">${dep.invoiceDesk}</a> · qorechain-diana (EVM 9800) · Apache-2.0 · built for QoreChain “Build Before Q-Day”, Post-Quantum AI Agents</footer>
</main></body></html>
`;
mkdirSync(new URL("docs/", root), { recursive: true });
writeFileSync(new URL("docs/index.html", root), html);
copyFileSync(new URL("assets/cover.png", root), new URL("docs/cover.png", root));
console.log(`docs/index.html: ${inbox.length} emails, ${(html.length / 1024).toFixed(0)} KB`);
