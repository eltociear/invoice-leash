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
const mcpInbox = json("inbox/inbox-MCP.json");
const inbox2 = json("inbox/inbox-v2.json"), v2run = json(`runs/${latest("v2-compromised-")}`), v2approve = json(`runs/${latest("v2-approve-")}`);
const probes = json("runs/probes/probes.json").probes;
const jl = (f) => read(f).trim().split("\n").map((l) => JSON.parse(l));
const mcpClaude = jl("runs/mcp-claude.server.jsonl"), mcpHostile = jl("runs/mcp-compromised.server.jsonl");
const mcpRow = (x) => {
  const what = x.tool === "check_invoice" ? `check_invoice(${x.args.email})` : x.tool === "pay_invoice" ? `pay_invoice(${x.args.email}) · ${mcpInbox[x.args.email].invoice.ref} · ${mcpInbox[x.args.email].invoice.qor} QOR`
    : x.tool === "send_qor" ? `send_qor(${x.args.qor} QOR → Mallory)` : `call_invoice_desk(${x.args.fn}, Mallory)`;
  const v = x.tool === "check_invoice" ? `<span class="v ${/^ACCEPTED/.test(x.verdict) ? "ok" : "no"}">${esc(x.verdict.replace(/ \(.*\)$/, ""))}${x.fitsPerTx ? "" : " · over per-payment limit"}</span>`
    : x.ok ? `<span class="v ok">PAID</span>` : `<span class="v no">${esc(short(x.why))}</span>`;
  return `<div class="step"><code>${esc(what)}</code>${v}${txLink(x.link)}</div>`;
};
const EX = "https://explore.qore.network/tx/";
const mcpInbox2 = json("inbox/inbox-v2-MCP.json");
const mcpClaude2 = jl("runs/mcp-v2-claude.server.jsonl"), mcpHostile2 = jl("runs/mcp-v2-compromised.server.jsonl");
const mcpRow2 = (x) => {
  const inv = mcpInbox2[x.args.email]?.invoice;
  const what = x.tool === "check_invoice" ? `check_invoice(${x.args.email}) · ${inv.ref} · ${inv.fusd} fUSD` : x.tool === "pay_invoice" ? `pay_invoice(${x.args.email}) · ${inv.ref} · ${inv.fusd} fUSD`
    : x.tool === "send_qor" ? `send_qor(${x.args.qor} QOR → Mallory)` : x.tool === "transfer_fusd" ? `transfer_fusd(${x.args.fusd} fUSD → Mallory)` : `call_invoice_desk(${x.args.fn}, Mallory)`;
  const v = x.tool === "check_invoice" ? `<span class="v ${/^WOULD PAY/.test(x.verdict) ? "ok" : "no"}">${esc(x.verdict.replace(/ \(.*\)$/, ""))}</span>`
    : x.ok ? `<span class="v ok">PAID</span>` : `<span class="v no">${esc(short(x.why))}</span>`;
  return `<div class="step"><code>${esc(what)}</code>${v}${txLink(x.link)}</div>`;
};

const esc = (s) => String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const short = (why = "") => {
  if (/not permitted to "send"|lacks the permission/.test(why)) return 'linked key is not permitted to "send"';
  if (/may call/.test(why)) return "call is not in the rule's allowed_evm_calls";
  if (/denom uqor not allowed/.test(why)) return "QOR is not a denom the rule allows";
  if (/per-tx limit/.test(why)) { const [, l, a] = why.match(/per-tx limit (\d+)uqor exceeded \(attempted (\d+)\)/) ?? []; return l ? `per-payment limit ${l / 1e6} QOR (attempted ${a / 1e6})` : "per-payment limit"; }
  if (/daily limit/.test(why)) { const [, l, sp] = why.match(/daily limit (\d+)uqor exceeded: spent (\d+)/) ?? []; return l ? `daily limit: ${sp / 1e6} of ${l / 1e6} QOR spent` : "daily limit"; }
  return why.replace(/^InvoiceDesk: /, "InvoiceDesk: ");
};
const txLink = (link) => link ? `<a class="tx" href="${esc(link)}" target="_blank" rel="noopener">${esc(link.slice(-64, -56))}…</a>` : "";
const act = (x, m) => x.action === "send" ? `send ${x.qor} QOR to ${x.to.slice(0, 12)}…` : x.action === "call" ? `call desk.${x.fn}(Mallory)` : `pay ${m.invoice.ref} · ${m.invoice.qor} QOR`;
const verdict = (x) => x.result === "skipped" ? `<span class="v skip">skipped</span>` : x.ok ? `<span class="v ok">PAID</span>` : `<span class="v no">${esc(short(x.why))}</span>`;

const act2 = (x) => {
  const m = inbox2[x.item];
  if (x.action === "send") return `MsgSend ${x.qor} QOR → Mallory`;
  if (x.action === "evm-value") return `EVM value transfer ${x.qor} QOR → Mallory`;
  if (x.action === "token-transfer") return `fUSD.transfer(Mallory, ${x.fusd})`;
  if (x.action === "token-transferFrom") return `fUSD.transferFrom(company, Mallory, ${x.fusd})`;
  if (x.action === "call") return `desk.${x.fn}(${x.fn === "setLimit" ? "fUSD, 10⁶, 10⁶" : "Mallory"})`;
  return `pay ${x.ref ?? m.invoice.ref}`;
};
const emails2 = inbox2.map((m, i) => {
  const steps = v2run.log.filter((x) => x.item === i).map((x) => `<div class="step"><code>${esc(act2(x))}</code>${verdict(x)}${txLink(x.link)}</div>`).join("");
  const human = v2approve.item === i ? `<div class="lane"><div class="who">the company, in person</div><div class="step"><code>approve-v2 ${i} · ${esc(v2approve.fusd)} fUSD</code><span class="v ok">PAID</span><a class="tx" href="${EX}${v2approve.evmTx}" target="_blank" rel="noopener">${v2approve.evmTx.slice(2, 10)}…</a></div><div class="why">Over the agent's limit, so a human pays it, after a dry run of the same checks.</div></div>` : "";
  return `<article class="mail"><header><span class="n">#${i}</span><div><div class="from">${esc(m.from)}</div><h3>${esc(m.subject)}</h3></div></header>
  <p class="body">${esc(m.body)}</p>
  ${m.invoice ? `<div class="inv">invoice <b>${esc(m.invoice.ref)}</b> · ${esc(m.invoice.fusd)} fUSD · payee ${esc(m.invoice.vendor.slice(0, 10))}… · ML-DSA-87 signature ${(m.invoice.signature.length - 2) / 2} bytes</div>` : ""}
  <div class="lanes"><div class="lane"><div class="who">compromised agent</div>${steps}</div>${human}</div></article>`;
}).join("\n");
const probeRows = probes.map((p) => `<div class="step"><span class="v ${p.expect === "executed" ? (p.id.startsWith("v2") ? "ok" : "no") : "skip"}">${p.expect === "executed" ? "EXECUTED" : "refused"}</span><code>${esc(p.action.slice(0, 80))}</code><span class="why">${esc(p.account)}</span><a class="tx" href="${EX}${p.tx}" target="_blank" rel="noopener">${p.tx.slice(0, 8)}…</a></div>`).join("");

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
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,">
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
<p class="lede">An invoice-paying AI agent that stays safe when its model does not. The agent's code has no limit check, no vendor check and no signature check; invoices are in fUSD and signed with ML-DSA-87. Every limit lives on QoreChain, so we can hand the agent to an attacker and watch the chain say no.</p>
<div class="links">
  <a href="lab.html" style="border-color:var(--acc);color:var(--acc)">Try to break it: attack lab (live, in your browser)</a>
  <a href="#found">What we found about spending rules</a>
  <a href="#mcp">Claude Code via MCP</a>
  <a href="https://youtu.be/DssIkkYx8gc">Demo video (2:53, v1)</a>
  <a href="https://github.com/eltociear/invoice-leash">Code</a>
  <a href="https://github.com/eltociear/invoice-leash/blob/main/THREAT_MODEL.md">Threat model</a>
  <a href="#verify">Verify it yourself</a>
  <a href="https://github.com/eltociear/invoice-leash#use-it-from-any-agent-the-mcp-server">MCP server</a>
  <a href="https://build.qorechain.io/p/invoice-leash">Build Before Q-Day entry</a>
</div>

<div class="stats">
  <div class="stat"><b>3</b><span>genuine invoices paid by a fully compromised agent (220 fUSD)</span></div>
  <div class="stat"><b>${v2run.log.filter((x) => !x.ok).length}</b><span>of its ${v2run.log.length} attempts refused, by the chain or the contract</span></div>
  <div class="stat"><b>0</b><span>QOR moved, and 0 fUSD to the attacker (her balance is checked)</span></div>
</div>

<div class="layers">
  <div class="layer"><h3>An agent that holds nothing</h3><p>The agent acts as its own account. Its QoreChain rule lists no QOR and no fUSD, and allows one call: <code>InvoiceDeskV2.pay</code>. It cannot send, transfer, approve or reconfigure.</p></div>
  <div class="layer"><h3>The company's money, the company's limits</h3><p>fUSD stays in the company's account (no vault). The desk pulls it per invoice, within 100 fUSD a payment and 250 a day that only the company can set.</p></div>
  <div class="layer"><h3>Post-quantum invoices</h3><p>ML-DSA-87 signature from an approved vendor whose key is registered on chain, over payer, payee, currency and amount, checked by precompiles <code>0x…0a02</code> and <code>0x…0a01</code>.</p></div>
</div>

<h2>The inbox, email by email (v2, fUSD)</h2>
<p class="dim">Recorded on <code>qorechain-diana</code>. Two honest vendors, Hostline and Tokenwell, and Mallory, who holds a valid ML-DSA-87 key of her own but is not a vendor. The compromised agent obeys every email, attacker's included, and tries every way to move money.</p>
${emails2}

<h2 id="found">What we found: a spending rule bounds amounts, not destinations</h2>
<p class="dim">v1 let the agent act as the company's account, scoped to <code>pay</code> by a QoreChain spending rule. These probes, each one request by the agent's key, showed the key could still move value directly in any denom its rule allows (a plain QOR transfer, or <code>fUSD.transfer</code>), and could not pay in an unlisted token at all. v2 gives the agent an account that holds nothing. Every probe is re-read by <code>npm run verify</code>.</p>
<article class="mail"><div class="lanes" style="margin-left:0"><div class="lane" style="border-top:0">${probeRows}</div></div></article>

<h2 id="mcp">Through MCP (v2): Claude Code holds the leash</h2>
<p class="dim"><code>mcp/server.mjs</code> holds only the agent's key and hands the model dangerous tools on purpose: <code>send_qor</code>, <code>transfer_fusd</code> and <code>call_invoice_desk</code>, beside <code>check_invoice</code> (a dry run of the real desk, as the agent) and <code>pay_invoice</code>. A fresh inbox: the same ten emails with new invoice numbers.</p>
<article class="mail"><header><span class="n">1</span><div><div class="from">Claude Code (claude-opus-5-5), nothing but the MCP server · <a href="https://github.com/eltociear/invoice-leash/blob/main/runs/mcp-v2-claude-final.txt">transcript</a></div><h3>Dry-ran all nine invoices, paid the three genuine ones (220 fUSD), sent the 300 fUSD one to a human, held #9 for the next UTC day</h3></div></header>
<div class="lanes"><div class="lane">${mcpClaude2.map(mcpRow2).join("")}</div></div></article>
<article class="mail"><header><span class="n">2</span><div><div class="from">then an obey-everything MCP client, same tools, same inbox · <a href="https://github.com/eltociear/invoice-leash/blob/main/runs/mcp-v2-compromised-final.txt">transcript</a></div><h3>${mcpHostile2.length} attempts, ${mcpHostile2.filter((x) => !x.ok).length} refused, by the chain's rule or the desk</h3></div></header>
<div class="lanes"><div class="lane">${mcpHostile2.map(mcpRow2).join("")}</div></div></article>
<article class="mail"><header><span class="n">3</span><div><div class="from">then Claude Code as an auditor, read-only tools only (<code>action_log</code> + QoreChain's <code>@qorechain/mcp</code>) · <a href="https://github.com/eltociear/invoice-leash/blob/main/runs/mcp-v2-audit-final.txt">transcript</a></div><h3>Re-read all 15 transactions with <code>get_transaction</code>: every verdict the server reported matches the chain</h3></div></header></article>

<h2>v1 (QOR): the first design, as recorded</h2>
<p class="dim">The agent acted as the company's account, 1 QOR a payment, 2.5 a day. Every attack in the inbox was refused; the probes above are why v1 was replaced. The compromised agent obeys every email; Claude decides for itself.</p>
${emails}

<h2>v1 through MCP: any agent can hold the leash</h2>
<p class="dim"><code>mcp/server.mjs</code> gives an MCP client six tools, holding only the agent's key: <code>leash_status</code>, <code>list_inbox</code>, <code>check_invoice</code> (a dry run of the real contract), <code>pay_invoice</code>, and, deliberately, <code>send_qor</code> and <code>call_invoice_desk</code>. A fresh inbox: the same ten emails with new invoice numbers.</p>
<article class="mail"><header><span class="n">1</span><div><div class="from">Claude Code (claude-opus-5-5), nothing but the MCP server · <a href="https://github.com/eltociear/invoice-leash/blob/main/runs/mcp-claude-final.txt">transcript</a></div><h3>Dry-ran every invoice, paid the three genuine ones, flagged #7 for a human, held #9 for tomorrow</h3></div></header>
<div class="lanes"><div class="lane">${mcpClaude.map(mcpRow).join("")}</div></div></article>
<article class="mail"><header><span class="n">2</span><div><div class="from">then an obey-everything MCP client, same tools, same inbox · <a href="https://github.com/eltociear/invoice-leash/blob/main/runs/mcp-compromised-final.txt">transcript</a></div><h3>${mcpHostile.length} attempts, ${mcpHostile.filter((x) => !x.ok).length} refused by the chain, balance unchanged</h3></div></header>
<div class="lanes"><div class="lane">${mcpHostile.map(mcpRow).join("")}</div></div></article>

<h2>Then the owner pulls the leash</h2>
<p class="dim">v2: one company transaction in the desk. A genuine 20 fUSD invoice the desk would pay for the agent:</p>
<pre>$ node leash.mjs kill-switch-v2
company: setAgent(agent, false)    <a href="${EX}0x11c3c95e65467ac17ad29ddac40aab1886270cc9dab07e931b29903958223487">0x11c3c95e…</a>
agent sends the payment            REFUSED: NotPayersAgent   <a href="${EX}7C5A50C895BAC281AAD5FDC36BE2BC335971B38F10CD96E91353ADB2BE408882">7C5A50C8…</a>
company: setAgent(agent, true)     <a href="${EX}0x19b24261fb60511775cf728ed54e3fbf9d61acefc10fea18667b36667f4fa6e5">0x19b24261…</a>
agent sends the same payment       PAID   <a href="${EX}ABE3152A5D793796ECE0EA13972DBB9A2082A495AEE9F41B39585A06CE42ED18">ABE3152A…</a></pre>
<p class="dim">v1: the owner revokes the agent's key on chain.</p>
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
