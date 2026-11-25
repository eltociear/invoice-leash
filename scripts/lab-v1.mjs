// Build docs/lab-v1.html: the v1 (QOR) attack lab that runs entirely in the visitor's browser against the live
// testnet. Tamper with a real ML-DSA-87 signed invoice and ask the real InvoiceDesk (eth_call) whether
// it would pay. No server, no keys, nothing sent, nothing spent.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from "node:fs";
import { qorToEvm } from "@qorechain/sdk";

const root = new URL("../", import.meta.url);
const json = (p) => JSON.parse(readFileSync(new URL(p, root), "utf8"));
const dep = json("deployment.json"), lab = json("inbox/inbox-LAB.json"), main = json("inbox/inbox.json");
const comp = json("runs/compromised-2026-11-21T12-21-33-825Z.json");
const payer = qorToEvm(dep.owner);
const pick = (m) => ({ vendor: m.invoice.vendor, amountWei: m.invoice.amountWei, ref: m.invoice.ref, id: m.invoice.id, dueBy: m.invoice.dueBy, signature: m.invoice.signature });
const data = {
  desk: dep.invoiceDesk, rpc: "https://evm-testnet.qore.host", chainId: dep.evmChainId, payer,
  payers: { [payer]: "the company (Claude/MCP run owner)", [qorToEvm(comp.owner)]: "another company (compromised-run owner)" },
  vendors: { ...Object.fromEntries(Object.entries(dep.vendors).map(([k, v]) => [v.toLowerCase(), k])), [dep.attacker.toLowerCase()]: "Mallory" },
  rule: { perTxQor: Number(dep.agentRule.perTx), dailyQor: Number(dep.agentRule.daily), call: dep.agentRule.allowedEvmCalls[0] },
  presets: [
    { key: "genuine", label: "A genuine invoice", note: "Tokenwell, 0.6 QOR, signed with Tokenwell's registered ML-DSA-87 key, never paid. Start here, then change one thing.", inv: pick(lab[9]) },
    { key: "forged", label: "Forged “Hostline” invoice", note: "Claims to be from Hostline, signed with Mallory's key.", inv: pick(lab[4]) },
    { key: "edited", label: "Edited amount", note: "Hostline's real signature; amount changed from 0.8 to 0.95 after signing.", inv: pick(lab[5]) },
    { key: "mallory", label: "Mallory's own invoice", note: "Correctly signed with Mallory's own registered key. She is just not a vendor.", inv: pick(lab[3]) },
    { key: "replay", label: "Replay a paid invoice", note: "Hostline's genuine invoice that the agent already paid on 2026-11-21.", inv: pick(main[0]) },
    { key: "big", label: "Genuine, but 5 QOR", note: "The contract would pay it. The agent's key still cannot: 1 QOR per payment.", inv: pick(lab[7]) },
  ],
};
const ERR = {
  UnknownVendor: "The payee is not on this company's approved-vendor list. Only the owner can approve vendors, and the agent's key cannot call approveVendor.",
  VendorKeyNotProven: "The payee has no ML-DSA-87 key registered on chain with proof of possession.",
  BadSignature: "The ML-DSA-87 signature does not match these exact bytes under the payee's registered key. Every field is signed: payer, payee, amount, invoice number, due date, this desk, this chain.",
  AlreadyPaid: "This company already paid this invoice number. Checked after the signature, so an edited copy is reported as the forgery it is.",
  PastDue: "Signature valid and unpaid, but past its due date.",
  WrongAmount: "The QOR sent with the call is not the invoiced amount.",
};

const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="data:,">
<title>Invoice Leash · attack lab</title>
<meta name="description" content="Tamper with a real ML-DSA-87 signed invoice and ask the real contract on the QoreChain testnet whether it would pay. In your browser, no keys.">
<style>
p, li, td, code, .mono { overflow-wrap: anywhere; }
:root{--bg:#0d1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;--ok:#3ddc97;--no:#ff7b72;--warn:#e3b341}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:1040px;margin:0 auto;padding:48px 24px 96px}a{color:var(--ok)}code,input,select,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
h1{font-size:38px;line-height:1.15;margin:0 0 10px}h2{font-size:20px;margin:28px 0 10px}.dim{color:var(--dim)}
.top{display:flex;gap:16px;flex-wrap:wrap;align-items:baseline;justify-content:space-between}.live{font-size:13px;color:var(--dim)}.dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--dim);margin-right:6px}.dot.on{background:var(--ok)}
.presets{display:flex;flex-wrap:wrap;gap:8px}.presets button{background:var(--panel);color:var(--fg);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font:inherit;font-size:14px;cursor:pointer}.presets button[aria-pressed=true]{border-color:var(--ok);color:var(--ok)}
.note{color:var(--dim);font-size:14px;margin:10px 0 0;min-height:22px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}
label{display:block;font-size:13px;color:var(--dim);margin:10px 0 4px}label:first-child{margin-top:0}
input,select{width:100%;background:var(--bg);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:13px}input.changed,select.changed{border-color:var(--warn)}
.row{display:flex;gap:8px}.row>*{flex:1}.sig{font-size:12px;color:var(--dim);word-break:break-all}
.btns{display:flex;gap:8px;margin-top:8px;flex-wrap:wrap}.btns button{background:transparent;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:6px 10px;font:13px inherit;cursor:pointer}
.go{display:block;width:100%;margin-top:16px;background:var(--ok);color:#0d1117;border:0;border-radius:8px;padding:12px;font:600 16px inherit;cursor:pointer}.go:disabled{opacity:.5;cursor:wait}
.verdict{font-size:24px;font-weight:700;margin:0 0 6px}.verdict.ok{color:var(--ok)}.verdict.no{color:var(--no)}.why{margin:0 0 12px}
.layer{border-top:1px solid var(--line);padding-top:10px;margin-top:10px;font-size:14px}.layer b{color:var(--fg)}.tag{font:600 12px ui-monospace,Menlo,monospace;padding:1px 6px;border-radius:5px;margin-right:6px}.tag.ok{background:var(--ok);color:#0d1117}.tag.no{border:1px solid #6e2b27;color:var(--no)}
.diff{font-size:13px;color:var(--warn)}.keys{font-size:13px}.keys div{display:flex;justify-content:space-between;border-top:1px solid var(--line);padding:6px 0}
ol.log{font-size:13px;color:var(--dim);padding-left:20px;margin:0}ol.log li{margin:3px 0}
@media (max-width:760px){.grid{grid-template-columns:1fr}h1{font-size:28px}}
</style></head>
<body><main>
<div class="top"><h1>Attack lab, v1 (QOR): make Invoice Leash pay</h1><a href="lab.html">← the v2 (fUSD) lab</a></div>
<p>Pick a real invoice, change anything, and ask the <b>real InvoiceDesk on the QoreChain testnet</b> whether it would pay. Your browser sends an <code>eth_call</code> to <code>${data.rpc}</code>; the ML-DSA-87 check is the chain's own precompile. Nothing is sent and nothing is spent, so try as much as you like.</p>
<p class="live"><span class="dot" id="dot"></span><span id="live">connecting to qorechain-diana…</span></p>

<h2>1. Start from</h2>
<div class="presets" id="presets"></div>
<p class="note" id="note"></p>

<div class="grid">
<div class="card">
  <h2 style="margin-top:0">2. The invoice</h2>
  <label for="payer">Payer (whose money)</label><select id="payer"></select>
  <label for="vendor">Payee</label><select id="vendor"></select>
  <div class="row"><div><label for="amount">Amount (QOR)</label><input id="amount" inputmode="decimal"></div><div><label for="value">QOR sent with the call</label><input id="value" inputmode="decimal"></div></div>
  <label for="ref">Invoice number (its id is keccak256 of this)</label><input id="ref">
  <label for="due">Due (UTC)</label><input id="due" type="datetime-local" step="1">
  <label>ML-DSA-87 signature</label><div class="sig mono" id="sig"></div>
  <div class="btns"><button type="button" id="flip">Flip one random bit</button><button type="button" id="reset">Undo all changes</button></div>
  <button class="go" id="go" type="button">Ask the chain</button>
</div>
<div class="card" id="out">
  <h2 style="margin-top:0">3. The chain's answer</h2>
  <p class="dim">Change something, then ask.</p>
</div>
</div>

<h2>What the vendors' keys look like on chain right now</h2>
<div class="card keys" id="keys"><span class="dim">reading pqcKeyStatus (precompile 0x…0a02)…</span></div>

<h2>What you cannot try here, and why</h2>
<div class="card"><ol class="log">
  <li><b>Send QOR straight to yourself.</b> The agent's key is linked with permission <code>evm</code> only: <a href="https://explore.qore.network/tx/444065FEA178910087098568FD448A8FD2DC0AB6BEBCBD148A5D1724E8C700AB">refused on chain</a>.</li>
  <li><b>Approve yourself as a vendor.</b> The rule allows exactly <code>${data.rule.call}</code> (InvoiceDesk.pay): <a href="https://explore.qore.network/tx/DACBD4A6D4C5EF8E1C45EFC215A6FE5B387F69BA2CF0F5BEA30EAFEA703505FC">refused on chain</a>.</li>
  <li><b>Many small genuine invoices.</b> ${data.rule.dailyQor} QOR per day: <a href="https://explore.qore.network/tx/4B82397AFE26F3DD0A356F75F5BAF36DCB92C8F2070DC1210FFCA32565F7B9B7">refused on chain</a>.</li>
  <li>Those need the agent's key, so they live in the <a href="./">recorded runs</a> and in <code>npm run verify</code>.</li>
</ol></div>
<p class="dim" style="margin-top:32px;font-size:14px">InvoiceDesk <a href="https://explore.qore.network/address/${data.desk}">${data.desk}</a> · qorechain-diana · <a href="https://github.com/eltociear/invoice-leash">code</a> · ABI encoding by <a href="https://github.com/ethers-io/ethers.js">ethers.js</a> (MIT), served from this site.</p>
</main>
<script src="vendor/ethers.umd.min.js"></script>
<script>
const D = ${JSON.stringify(data)};
const ERR = ${JSON.stringify(ERR)};
const E = window.ethers;
const desk = new E.Interface([
  "function pay(address vendor,uint256 amount,bytes32 id,uint64 dueBy,bytes signature) payable",
  "error UnknownVendor(address vendor)","error VendorKeyNotProven(address vendor)","error BadSignature()",
  "error AlreadyPaid(bytes32 id)","error PastDue(uint64 dueBy)","error WrongAmount(uint256 sent,uint256 invoiced)","error TransferFailed()"]);
const status = new E.Interface(["function pqcKeyStatus(address) view returns (bool registered,uint8 algorithmId,bytes pubkey,bool possessionProven)"]);
const $ = (id) => document.getElementById(id);
let base, cur;
async function rpc(method, params) {
  const r = await fetch(D.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
  if (!r.ok) throw new Error("the testnet RPC answered HTTP " + r.status);
  return r.json();
}
const qor = (wei) => E.formatUnits(wei, 18).replace(/\\.0$/, "");
const toWei = (q) => { try { return E.parseUnits(String(q).trim() || "0", 18); } catch { return null; } };
const isoLocal = (t) => new Date(t * 1000).toISOString().slice(0, 19);
const name = (a) => D.vendors[a.toLowerCase()] ?? a;

function fill() {
  $("payer").innerHTML = Object.entries(D.payers).map(([a, n]) => '<option value="' + a + '">' + n + " · " + a.slice(0, 10) + "…</option>").join("");
  $("vendor").innerHTML = Object.entries(D.vendors).map(([a, n]) => '<option value="' + a + '">' + n + " · " + a.slice(0, 10) + "…</option>").join("");
}
function load(p) {
  base = { payer: D.payer, vendor: p.inv.vendor.toLowerCase(), amount: qor(p.inv.amountWei), value: qor(p.inv.amountWei), ref: p.inv.ref, dueBy: p.inv.dueBy, signature: p.inv.signature };
  cur = { ...base };
  document.querySelectorAll("#presets button").forEach((b) => b.setAttribute("aria-pressed", b.dataset.key === p.key));
  $("note").textContent = p.note;
  render();
  $("out").innerHTML = '<h2 style="margin-top:0">3. The chain\\'s answer</h2><p class="dim">Ask as it is, or change something first.</p>';
}
function render() {
  $("payer").value = cur.payer; $("vendor").value = cur.vendor; $("amount").value = cur.amount; $("value").value = cur.value;
  $("ref").value = cur.ref; $("due").value = isoLocal(cur.dueBy);
  const s = cur.signature;
  $("sig").textContent = (s.length - 2) / 2 + " bytes · " + s.slice(0, 26) + "…" + s.slice(-16) + (s !== base.signature ? "  (tampered)" : "");
  for (const k of ["payer", "vendor", "amount", "value", "ref"]) $(k).classList.toggle("changed", String(cur[k]) !== String(base[k]));
  $("due").classList.toggle("changed", cur.dueBy !== base.dueBy);
}
function changes() {
  const c = [];
  if (cur.payer !== base.payer) c.push("payer");
  if (cur.vendor !== base.vendor) c.push("payee");
  if (cur.amount !== base.amount) c.push("amount");
  if (cur.ref !== base.ref) c.push("invoice number");
  if (cur.dueBy !== base.dueBy) c.push("due date");
  if (cur.signature !== base.signature) c.push("signature");
  if (cur.value !== base.value) c.push("QOR sent");
  return c;
}
async function ask() {
  try { await ask1(); } catch (e) { $("out").innerHTML = '<p class="verdict no">Could not reach the testnet</p>'; $("out").append(String(e.message) + " Try again in a moment."); } finally { $("go").disabled = false; }
}
async function ask1() {
  const amount = toWei(cur.amount), value = toWei(cur.value);
  if (amount === null || value === null) { $("out").innerHTML = '<p class="verdict no">Not a number</p>'; return; }
  $("go").disabled = true;
  const t0 = performance.now();
  const data = desk.encodeFunctionData("pay", [cur.vendor, amount, E.keccak256(E.toUtf8Bytes(cur.ref)), cur.dueBy, cur.signature]);
  const [res, blk] = await Promise.all([rpc("eth_call", [{ from: cur.payer, to: D.desk, value: E.toQuantity(value), data }, "latest"]), rpc("eth_blockNumber", [])]);
  const ms = Math.round(performance.now() - t0);
  $("go").disabled = false;
  let ok = false, title, why;
  if (res.result !== undefined) { ok = true; title = "InvoiceDesk would PAY this"; why = "Approved payee, valid ML-DSA-87 signature over these exact bytes, unpaid, not past due, right amount."; }
  else {
    const d = res.error?.data; let n = null;
    try { n = d ? desk.parseError(d)?.name : null; } catch {}
    if (n) { title = "REFUSED: " + n; why = ERR[n] ?? ""; }
    else if (/insufficient/i.test(res.error?.message ?? "")) { title = "Refused before the contract ran"; why = "The payer's balance is lower than the QOR you are sending. (The signature is checked first, so try sending 0.)"; }
    else { title = "Error"; why = res.error?.message ?? "no answer"; }
  }
  const c = changes();
  const overTx = Number(cur.amount) > D.rule.perTxQor;
  const leash = overTx
    ? '<span class="tag no">REFUSED</span> over the agent\\'s ' + D.rule.perTxQor + ' QOR per-payment limit: the chain refuses before the contract runs. A human pays this one.'
    : '<span class="tag ok">within</span> ' + D.rule.perTxQor + " QOR per payment (and the " + D.rule.dailyQor + " QOR daily limit is checked at payment time).";
  $("out").innerHTML = '<h2 style="margin-top:0">3. The chain\\'s answer</h2>' +
    '<p class="verdict ' + (ok ? "ok" : "no") + '">' + title + '</p><p class="why">' + why + "</p>" +
    (c.length ? '<p class="diff">You changed: ' + c.join(", ") + "</p>" : '<p class="dim" style="font-size:14px">No changes from the preset.</p>') +
    '<div class="layer"><b>Layer 1, the contract</b> (what you just asked): ' + (ok ? '<span class="tag ok">PAY</span>' : '<span class="tag no">REFUSE</span>') + "</div>" +
    '<div class="layer"><b>Layer 2, the agent\\'s leash</b> (spending rule on the payer\\'s account, enforced first): ' + leash + "</div>" +
    '<p class="dim" style="font-size:13px;margin-top:12px">eth_call to InvoiceDesk at block ' + parseInt(blk.result, 16).toLocaleString() + " · " + ms + " ms · payee " + name(cur.vendor) + "</p>";
}
async function keys() {
  const rows = [];
  for (const [a, n] of Object.entries(D.vendors)) {
    const r = await rpc("eth_call", [{ to: "0x0000000000000000000000000000000000000a02", data: status.encodeFunctionData("pqcKeyStatus", [a]) }, "latest"]);
    const [reg, alg, pk, proven] = status.decodeFunctionResult("pqcKeyStatus", r.result);
    rows.push("<div><span>" + n + ' <span class="dim mono">' + a.slice(0, 12) + "…</span></span><span class=mono>" + (reg ? "registered" : "none") + " · " + (Number(alg) === 1 ? "ML-DSA-87" : "alg " + alg) + " · " + (pk.length - 2) / 2 + " B · " + (proven ? "possession proven" : "not proven") + "</span></div>");
  }
  $("keys").innerHTML = rows.join("") + '<p class="dim" style="margin:8px 0 0">Mallory\\'s key is as valid as the vendors\\'. What she lacks is a place on the payer\\'s approved list.</p>';
}
$("presets").innerHTML = D.presets.map((p) => '<button type="button" data-key="' + p.key + '">' + p.label + "</button>").join("");
document.querySelectorAll("#presets button").forEach((b) => b.onclick = () => load(D.presets.find((p) => p.key === b.dataset.key)));
fill();
for (const k of ["payer", "vendor", "amount", "value", "ref"]) $(k).oninput = (e) => { cur[k] = e.target.value; render(); };
$("due").oninput = (e) => { const t = Date.parse(e.target.value + "Z"); if (!isNaN(t)) { cur.dueBy = Math.floor(t / 1000); render(); } };
$("flip").onclick = () => { const b = E.getBytes(cur.signature).slice(); const i = Math.floor(Math.random() * b.length); b[i] ^= 1 << Math.floor(Math.random() * 8); cur.signature = E.hexlify(b); render(); };
$("reset").onclick = () => { cur = { ...base }; render(); };
$("go").onclick = ask;
load(D.presets[0]);
rpc("eth_blockNumber", []).then((r) => { $("dot").classList.add("on"); $("live").textContent = "live: qorechain-diana, block " + parseInt(r.result, 16).toLocaleString(); }).catch(() => { $("live").textContent = "could not reach the testnet RPC"; });
keys().catch(() => { $("keys").textContent = "could not read key status"; });
</script>
</body></html>
`;
mkdirSync(new URL("docs/vendor/", root), { recursive: true });
copyFileSync(new URL("node_modules/ethers/dist/ethers.umd.min.js", root), new URL("docs/vendor/ethers.umd.min.js", root));
copyFileSync(new URL("node_modules/ethers/LICENSE.md", root), new URL("docs/vendor/ethers-LICENSE.md", root));
writeFileSync(new URL("docs/lab-v1.html", root), html);
console.log(`docs/lab-v1.html: ${data.presets.length} presets, ${(html.length / 1024).toFixed(0)} KB`);
