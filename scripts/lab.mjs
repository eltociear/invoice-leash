// Build docs/lab.html: the v2 (fUSD) attack lab. Runs entirely in the visitor's browser against the
// live testnet: tamper with a real ML-DSA-87 signed invoice, choose who sends it, and ask the real
// InvoiceDeskV2 (eth_call) whether it would pay. No server, no keys, nothing sent, nothing spent.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, readdirSync } from "node:fs";

const root = new URL("../", import.meta.url);
const json = (p) => JSON.parse(readFileSync(new URL(p, root), "utf8"));
const dep = json("deployment.json"), d2 = dep.v2, lab = json("inbox/inbox-v2-LAB.json"), main = json("inbox/inbox-v2.json");
const run = json("runs/" + readdirSync(new URL("runs/", root)).filter((f) => /^v2-compromised-.*\.json$/.test(f)).sort().pop());
const tx = (pred) => run.log.find(pred)?.link;
const pick = (inv) => ({ token: inv.token, vendor: inv.vendor, amount: inv.amount, ref: inv.ref, dueBy: inv.dueBy, signature: inv.signature });
const ZERO = "0x0000000000000000000000000000000000000000", FETH = "0x02292293c13880a26242690eb70a0e42B8E91c28";
const data = {
  desk: d2.invoiceDesk, rpc: "https://evm-testnet.qore.host", payer: d2.payerEvm, agent: d2.agentAccountEvm, fusd: d2.token,
  senders: { [d2.agentAccountEvm]: "the agent's account (what a hijacked agent would send)", [d2.payerEvm]: "the company in person (the human approval path)", [dep.attacker]: "a stranger (Mallory's account)" },
  payers: { [d2.payerEvm]: "the company", [dep.attacker]: "someone else (Mallory)" },
  tokens: { [d2.token]: ["fUSD", 6], [ZERO]: ["QOR (native)", 18], [FETH]: ["fETH", 18] },
  vendors: { ...Object.fromEntries(Object.entries(dep.vendors).map(([k, v]) => [v.toLowerCase(), k])), [dep.attacker.toLowerCase()]: "Mallory" },
  presets: [
    { key: "genuine", label: "A genuine invoice", note: "Tokenwell, 60 fUSD, signed with Tokenwell's registered ML-DSA-87 key, never paid. Ask as the agent, then change one thing.", inv: pick(lab[9].invoice) },
    { key: "forged", label: "Forged “Hostline” invoice", note: "Claims to be from Hostline, signed with Mallory's key.", inv: pick(lab[4].invoice) },
    { key: "edited", label: "Edited amount", note: "Hostline's real signature; amount changed from 80 to 95 fUSD after signing.", inv: pick(lab[5].invoice) },
    { key: "inqor", label: "“Pay it in QOR instead”", note: "Hostline's real signature on an 80 fUSD invoice, presented as 80 QOR. The currency is signed.", inv: pick(lab[6].attacks[0].invoice) },
    { key: "mallory", label: "Mallory's own invoice", note: "Correctly signed with Mallory's own registered key. She is just not a vendor.", inv: pick(lab[3].invoice) },
    { key: "replay", label: "Replay a paid invoice", note: "Hostline's 80 fUSD invoice that the agent already paid in the recorded v2 run.", inv: pick(main[0].invoice) },
    { key: "big", label: "Genuine, but 300 fUSD", note: "Over the agent's 100 fUSD per-payment limit. Ask as the agent, then as the company.", inv: pick(lab[7].invoice) },
  ],
  chainRefusals: [
    ["MsgSend 50 QOR", "no send permission", tx((x) => x.action === "send")],
    ["EVM value transfer, 0.5 QOR", "denom uqor not allowed", tx((x) => x.action === "evm-value")],
    ["fUSD.transfer(Mallory, 50)", "not an allowed call", tx((x) => x.action === "token-transfer")],
    ["fUSD.transferFrom(company, Mallory, 50)", "not an allowed call", tx((x) => x.action === "token-transferFrom")],
    ["desk.approveVendor(Mallory)", "not an allowed call", tx((x) => x.action === "call" && x.fn === "approveVendor")],
    ["desk.setLimit(fUSD, 10⁶, 10⁶)", "not an allowed call", tx((x) => x.action === "call" && x.fn === "setLimit")],
  ],
};
const ERR = {
  NotPayersAgent: "The sender is neither the company nor an agent the company named. Only the company can name agents.",
  UnknownVendor: "The payee is not on the company's approved-vendor list. Only the company can approve vendors; the agent's key cannot even call approveVendor.",
  VendorKeyNotProven: "The payee has no ML-DSA-87 key registered on chain with proof of possession.",
  BadSignature: "The ML-DSA-87 signature does not match these exact bytes under the payee's registered key. Every field is signed: payer, payee, currency, amount, invoice number, due date, this desk, this chain.",
  AlreadyPaid: "The company already paid this invoice number. Checked after the signature, so an edited copy is reported as the forgery it is.",
  PastDue: "Signature valid and unpaid, but past its due date.",
  AgentCannotPayNative: "Agents pay in ERC-20 only. (The agent's account could not move QOR anyway: its chain rule lists no QOR.)",
  OverPerPaymentLimit: "Over the per-payment limit the company set for its agents in fUSD. A human pays this one.",
  OverDailyLimit: "Over what the company's agents may still pay in fUSD today. The daily limit resets at 00:00 UTC; on a day the agent already paid, ask as the company to see every other check pass.",
  WrongAmount: "The QOR sent with the call is not what the invoice says.",
  TransferFailed: "The token transfer failed (allowance or balance).",
};

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,">
<title>Invoice Leash · attack lab (fUSD)</title>
<meta name="description" content="Tamper with a real ML-DSA-87 signed fUSD invoice and ask the real contract on the QoreChain testnet whether it would pay. In your browser, no keys.">
<style>
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;--ok:#3ddc97;--no:#ff7b72;--warn:#e3b341}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:1040px;margin:0 auto;padding:48px 24px 96px}a{color:var(--ok)}code,input,select,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
h1{font-size:38px;line-height:1.15;margin:0 0 10px}h2{font-size:20px;margin:28px 0 10px}.dim{color:var(--dim)}
.top{display:flex;gap:16px;flex-wrap:wrap;align-items:baseline;justify-content:space-between}.live{font-size:13px;color:var(--dim)}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--dim);margin-right:6px}.dot.on{background:var(--ok)}
.presets{display:flex;flex-wrap:wrap;gap:8px}.presets button{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font:inherit;font-size:14px;cursor:pointer}.presets button[aria-pressed=true]{border-color:var(--ok);color:var(--ok)}
.note{color:var(--dim);font-size:14px;margin:10px 0 0;min-height:22px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}
label{display:block;font-size:13px;color:var(--dim);margin:10px 0 4px}
input,select{width:100%;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:13px}input.changed,select.changed{border-color:var(--warn)}
.row{display:flex;gap:8px}.row>*{flex:1}.sig{font-size:12px;color:var(--dim);word-break:break-all}
.btns{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}.btns button{background:transparent;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 10px;font:13px inherit;cursor:pointer}
.go{display:block;width:100%;margin-top:16px;background:var(--ok);color:#0d1117;border:0;border-radius:8px;padding:12px;font:600 16px inherit;cursor:pointer}.go:disabled{opacity:.5;cursor:wait}
.verdict{font-size:24px;font-weight:700;margin:0 0 6px}.verdict.ok{color:var(--ok)}.verdict.no{color:var(--no)}.why{margin:0 0 12px}
.diff{font-size:13px;color:var(--warn)}.kv{font-size:13px}.kv div{display:flex;justify-content:space-between;gap:12px;border-top:1px solid var(--line);padding:6px 0}
ol.log{font-size:13px;color:var(--dim);padding-left:20px;margin:0}ol.log li{margin:3px 0}
@media (max-width:760px){.grid{grid-template-columns:1fr}h1{font-size:28px}.kv div{flex-direction:column;gap:2px}}
</style></head>
<body><main>
<div class="top"><h1>Attack lab: make Invoice Leash pay</h1><a href="./">← the recorded runs</a></div>
<p>Pick a real fUSD invoice, change anything, choose who sends it, and ask the <b>real InvoiceDeskV2 on the QoreChain testnet</b> whether it would pay. Your browser sends an <code>eth_call</code> to <code>${data.rpc}</code>; the ML-DSA-87 check is the chain's own precompile. Nothing is sent and nothing is spent, so try as much as you like.</p>
<p class="live"><span class="dot" id="dot"></span><span id="live">connecting to qorechain-diana…</span></p>

<h2>1. Start from</h2>
<div class="presets" id="presets"></div>
<p class="note" id="note"></p>

<div class="grid">
<div class="card">
  <h2 style="margin-top:0">2. The invoice, and who sends it</h2>
  <label for="sender">Sent by</label><select id="sender"></select>
  <label for="payer">Payer (whose money)</label><select id="payer"></select>
  <label for="vendor">Payee</label><select id="vendor"></select>
  <div class="row"><div><label for="token">Currency</label><select id="token"></select></div><div><label for="amount">Amount</label><input id="amount" inputmode="decimal"></div></div>
  <label for="ref">Invoice number (its id is keccak256 of this)</label><input id="ref">
  <label for="due">Due (UTC)</label><input id="due" type="datetime-local" step="1">
  <label>ML-DSA-87 signature</label><div class="sig mono" id="sig"></div>
  <div class="btns"><button type="button" id="flip">Flip one random bit</button><button type="button" id="reset">Undo all changes</button></div>
  <button class="go" id="go" type="button">Ask the chain</button>
</div>
<div class="card" id="out"><h2 style="margin-top:0">3. The chain's answer</h2><p class="dim">Change something, then ask.</p></div>
</div>

<h2>The company's leash on its agent, read live</h2>
<div class="card kv" id="state"><span class="dim">reading…</span></div>

<h2>What the agent's key cannot even send</h2>
<div class="card"><p class="dim" style="margin-top:0">The agent's own account holds nothing, its QoreChain rule lists no QOR and no fUSD, and it may make one call: <code>InvoiceDeskV2.pay</code>. These need the agent's key, so they are recorded rather than tried here; every one is refused by the chain:</p><ol class="log" id="refusals"></ol></div>
<p class="dim" style="margin-top:32px;font-size:14px">InvoiceDeskV2 <a href="https://explore.qore.network/address/${data.desk}">${data.desk}</a> · qorechain-diana · <a href="lab-v1.html">v1 lab (QOR)</a> · <a href="https://github.com/eltociear/invoice-leash">code</a> · ABI encoding by <a href="https://github.com/ethers-io/ethers.js">ethers.js</a> (MIT), served from this site.</p>
</main>
<script src="vendor/ethers.umd.min.js"></script>
<script>
const D = ${JSON.stringify(data)};
const ERR = ${JSON.stringify(ERR)};
const E = window.ethers;
const desk = new E.Interface([
  "function pay(address payer,address token,address vendor,uint256 amount,bytes32 id,uint64 dueBy,bytes signature) payable",
  "function limits(address,address) view returns (uint256 perPayment,uint256 daily)", "function remainingToday(address,address) view returns (uint256)",
  "function isAgent(address,address) view returns (bool)",
  "error NotPayersAgent(address caller)","error UnknownVendor(address vendor)","error VendorKeyNotProven(address vendor)","error BadSignature()",
  "error AlreadyPaid(bytes32 id)","error PastDue(uint64 dueBy)","error AgentCannotPayNative()","error OverPerPaymentLimit(uint256 amount,uint256 limit)",
  "error OverDailyLimit(uint256 spentToday,uint256 amount,uint256 limit)","error WrongAmount(uint256 sent,uint256 invoiced)","error TransferFailed()"]);
const erc20 = new E.Interface(["function balanceOf(address) view returns (uint256)", "function allowance(address,address) view returns (uint256)"]);
const status = new E.Interface(["function pqcKeyStatus(address) view returns (bool registered,uint8 algorithmId,bytes pubkey,bool possessionProven)"]);
const $ = (id) => document.getElementById(id);
let base, cur;
async function rpc(method, params) { const r = await fetch(D.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) }); return r.json(); }
const call = async (to, i, fn, args) => i.decodeFunctionResult(fn, (await rpc("eth_call", [{ to, data: i.encodeFunctionData(fn, args) }, "latest"])).result);
const dec = (t) => (D.tokens[t.toLowerCase()] ?? D.tokens[t] ?? ["token", 18])[1];
const unit = (t) => (D.tokens[t.toLowerCase()] ?? D.tokens[t] ?? ["token"])[0];
const toUnits = (q, t) => { try { return E.parseUnits(String(q).trim() || "0", dec(t)); } catch { return null; } };
const fromUnits = (a, t) => E.formatUnits(a, dec(t)).replace(/\\.0$/, "");
const isoLocal = (t) => new Date(t * 1000).toISOString().slice(0, 19);
const name = (a) => D.vendors[a.toLowerCase()] ?? a;
const opts = (o) => Object.entries(o).map(([a, n]) => '<option value="' + a + '">' + (Array.isArray(n) ? n[0] : n) + (a.length === 42 && !Array.isArray(n) ? " · " + a.slice(0, 10) + "…" : "") + "</option>").join("");
function fill() { $("sender").innerHTML = opts(D.senders); $("payer").innerHTML = opts(D.payers); $("vendor").innerHTML = opts(D.vendors); $("token").innerHTML = opts(D.tokens); }
function load(p) {
  const t = p.inv.token;
  base = { sender: D.agent, payer: D.payer, vendor: p.inv.vendor.toLowerCase(), token: Object.keys(D.tokens).find((k) => k.toLowerCase() === t.toLowerCase()), amount: fromUnits(p.inv.amount, t), ref: p.inv.ref, dueBy: p.inv.dueBy, signature: p.inv.signature };
  cur = { ...base };
  document.querySelectorAll("#presets button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.key === p.key));
  $("note").textContent = p.note; render();
  $("out").innerHTML = '<h2 style="margin-top:0">3. The chain\\'s answer</h2><p class="dim">Ask as it is, or change something first.</p>';
}
function render() {
  for (const k of ["sender", "payer", "vendor", "token", "amount", "ref"]) { $(k).value = cur[k]; $(k).classList.toggle("changed", String(cur[k]) !== String(base[k])); }
  $("due").value = isoLocal(cur.dueBy); $("due").classList.toggle("changed", cur.dueBy !== base.dueBy);
  const s = cur.signature; $("sig").textContent = (s.length - 2) / 2 + " bytes · " + s.slice(0, 26) + "…" + s.slice(-16) + (s !== base.signature ? "  (tampered)" : "");
}
function changes() {
  const c = []; const L = { payer: "payer", vendor: "payee", token: "currency", amount: "amount", ref: "invoice number" };
  for (const k in L) if (String(cur[k]) !== String(base[k])) c.push(L[k]);
  if (cur.dueBy !== base.dueBy) c.push("due date"); if (cur.signature !== base.signature) c.push("signature");
  return c;
}
async function ask() {
  const amount = toUnits(cur.amount, cur.token);
  if (amount === null) { $("out").innerHTML = '<p class="verdict no">Not a number</p>'; return; }
  $("go").disabled = true;
  const t0 = performance.now(), native = /^0x0+$/.test(cur.token);
  const data = desk.encodeFunctionData("pay", [cur.payer, cur.token, cur.vendor, amount, E.keccak256(E.toUtf8Bytes(cur.ref)), cur.dueBy, cur.signature]);
  const [res, blk] = await Promise.all([rpc("eth_call", [{ from: cur.sender, to: D.desk, value: E.toQuantity(native ? amount : 0n), data }, "latest"]), rpc("eth_blockNumber", [])]);
  const ms = Math.round(performance.now() - t0); $("go").disabled = false;
  let ok = false, title, why;
  if (res.result !== undefined) { ok = true; title = "InvoiceDeskV2 would PAY this"; why = cur.sender.toLowerCase() === D.agent.toLowerCase() ? "Named agent, approved payee, valid ML-DSA-87 signature over these exact bytes, unpaid, not past due, within the company's limits for its agents." : "The company in person: approved payee, valid ML-DSA-87 signature, unpaid, not past due. (Agent limits bind agents only.)"; }
  else {
    const d = res.error?.data; let n = null; try { n = d ? desk.parseError(d)?.name : null; } catch {}
    if (n) { title = "REFUSED: " + n; why = ERR[n] ?? ""; }
    else if (/insufficient/i.test(res.error?.message ?? "")) {
      title = "Refused before the contract ran";
      why = cur.sender.toLowerCase() === D.agent.toLowerCase() && native
        ? 'The agent\'s account cannot send that QOR: it holds almost none, and its chain rule allows no QOR at all (<a href="' + D.chainRefusals[1][2] + '">denom uqor not allowed</a>). Ask as the company to see the signature check: the currency is signed.'
        : "The sender's balance is lower than the QOR sent with the call.";
    }
    else { title = "Error"; why = res.error?.message ?? "no answer"; }
  }
  const c = changes();
  $("out").innerHTML = '<h2 style="margin-top:0">3. The chain\\'s answer</h2><p class="verdict ' + (ok ? "ok" : "no") + '">' + title + '</p><p class="why">' + why + "</p>" +
    (c.length ? '<p class="diff">You changed: ' + c.join(", ") + "</p>" : '<p class="dim" style="font-size:14px">No changes from the preset.</p>') +
    '<p class="dim" style="font-size:13px;margin-top:12px">eth_call from ' + (D.senders[cur.sender] ?? cur.sender) + " · block " + parseInt(blk.result, 16).toLocaleString() + " · " + ms + " ms · " + cur.amount + " " + unit(cur.token) + " to " + name(cur.vendor) + "</p>";
}
async function state() {
  const [bal] = await call(D.fusd, erc20, "balanceOf", [D.payer]), [allow] = await call(D.fusd, erc20, "allowance", [D.payer, D.desk]);
  const [mine] = await call(D.fusd, erc20, "balanceOf", [D.agent]), [named] = await call(D.desk, desk, "isAgent", [D.payer, D.agent]);
  const lim = await call(D.desk, desk, "limits", [D.payer, D.fusd]), [left] = await call(D.desk, desk, "remainingToday", [D.payer, D.fusd]);
  const f = (x) => E.formatUnits(x, 6).replace(/\\.0$/, "") + " fUSD";
  const rows = [["The company's fUSD (it never leaves the company's account until a payment)", f(bal)], ["What the desk may pull (the company's allowance)", f(allow)],
    ["The agent's own account holds", f(mine)], ["Named as the company's agent", named ? "yes" : "no"], ["Agent limit per payment / per day", f(lim[0]) + " / " + f(lim[1])], ["Left for the agent today (UTC)", f(left)]];
  for (const [a, n] of Object.entries(D.vendors)) {
    const r = await rpc("eth_call", [{ to: "0x0000000000000000000000000000000000000a02", data: status.encodeFunctionData("pqcKeyStatus", [a]) }, "latest"]);
    const [reg, alg, pk, proven] = status.decodeFunctionResult("pqcKeyStatus", r.result);
    rows.push([n + "'s key (" + a.slice(0, 10) + "…)", (reg ? "registered" : "none") + " · " + (Number(alg) === 1 ? "ML-DSA-87" : "alg " + alg) + " · " + (pk.length - 2) / 2 + " B · " + (proven ? "proven" : "not proven")]);
  }
  $("state").innerHTML = rows.map(([k, v]) => "<div><span>" + k + '</span><span class="mono">' + v + "</span></div>").join("") + '<p class="dim" style="margin:8px 0 0">Mallory\\'s key is as valid as the vendors\\'. What she lacks is a place on the company\\'s approved list.</p>';
}
$("presets").innerHTML = D.presets.map((p) => '<button type="button" data-key="' + p.key + '">' + p.label + "</button>").join("");
document.querySelectorAll("#presets button").forEach((b) => b.onclick = () => load(D.presets.find((p) => p.key === b.dataset.key)));
$("refusals").innerHTML = D.chainRefusals.map(([a, why, l]) => "<li><b>" + a + "</b>: " + why + ' · <a href="' + l + '">refused on chain</a></li>').join("");
fill();
for (const k of ["sender", "payer", "vendor", "token", "amount", "ref"]) $(k).oninput = (e) => { cur[k] = e.target.value; render(); };
$("due").oninput = (e) => { const t = Date.parse(e.target.value + "Z"); if (!isNaN(t)) { cur.dueBy = Math.floor(t / 1000); render(); } };
$("flip").onclick = () => { const b = E.getBytes(cur.signature).slice(); const i = Math.floor(Math.random() * b.length); b[i] ^= 1 << Math.floor(Math.random() * 8); cur.signature = E.hexlify(b); render(); };
$("reset").onclick = () => { cur = { ...base }; render(); };
$("go").onclick = ask;
load(D.presets[0]);
rpc("eth_blockNumber", []).then((r) => { $("dot").classList.add("on"); $("live").textContent = "live: qorechain-diana, block " + parseInt(r.result, 16).toLocaleString(); }).catch(() => { $("live").textContent = "could not reach the testnet RPC"; });
state().catch((e) => { $("state").textContent = "could not read the chain: " + e.message; });
</script>
</body></html>
`;
mkdirSync(new URL("docs/vendor/", root), { recursive: true });
copyFileSync(new URL("node_modules/ethers/dist/ethers.umd.min.js", root), new URL("docs/vendor/ethers.umd.min.js", root));
copyFileSync(new URL("node_modules/ethers/LICENSE.md", root), new URL("docs/vendor/ethers-LICENSE.md", root));
writeFileSync(new URL("docs/lab.html", root), html);
console.log(`docs/lab.html: ${data.presets.length} presets (v2, fUSD), ${(html.length / 1024).toFixed(0)} KB`);
