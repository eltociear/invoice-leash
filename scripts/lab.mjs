// Build docs/lab.html: the v2 (fUSD) attack lab. Runs entirely in the visitor's browser against the
// live testnet: tamper with a real ML-DSA-87 signed invoice, choose who sends it, and ask the real
// InvoiceDeskV2 (eth_call) whether it would pay. No server, no keys, nothing sent, nothing spent.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync, readdirSync } from "node:fs";
import { qorToEvm } from "@qorechain/sdk";

const root = new URL("../", import.meta.url);
const json = (p) => JSON.parse(readFileSync(new URL(p, root), "utf8"));
const dep = json("deployment.json"), d2 = dep.v2, lab = json("inbox/inbox-v2-LAB.json"), main = json("inbox/inbox-v2.json");
const run = json("runs/" + readdirSync(new URL("runs/", root)).filter((f) => /^v2-compromised-.*\.json$/.test(f)).sort().pop());
const tx = (pred) => run.log.find(pred)?.link;
const pick = (inv) => ({ token: inv.token, vendor: inv.vendor, amount: inv.amount, ref: inv.ref, dueBy: inv.dueBy, signature: inv.signature });
const ZERO = "0x0000000000000000000000000000000000000000", FETH = "0x02292293c13880a26242690eb70a0e42B8E91c28";
const data = {
  desk: d2.invoiceDesk, rpc: "https://evm-testnet.qore.host", payer: d2.payerEvm, company: d2.payer, agent: d2.agentAccountEvm, fusd: d2.token,
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
  pub: (({ address, evmAddress, secp256k1PrivateKey }) => ({ address, evm: evmAddress, key: secp256k1PrivateKey }))(json("runs/qday-public.json")), attacker: dep.attacker,
  v4: (() => { const l = json("runs/live/v4-lab-invoice.json"), pr = json("runs/probes/v4-agent-sig.json"); return { desk: l.desk, payer: l.payer, agent: l.agent, inv: l.invoice, paidLink: pr.steps[1].link, refusedLink: pr.steps[0].link }; })(),
  messages: json("runs/messages.json").map((m) => ({ name: m.name, signer: m.signer, signerEvm: qorToEvm(m.signer), text: m.text, chainId: m.chainId, pq: m.signature.pq.signature, expect: m.expect })),
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
p, li, td, code, .mono { overflow-wrap: anywhere; }
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
.you{margin-top:16px}.you .btns button.main{border-color:var(--ok);color:var(--ok)}.local{font-size:14px;border-top:1px solid var(--line);margin-top:12px;padding-top:10px}.local b.ok{color:var(--ok)}.local b.no{color:var(--no)}
@media (max-width:760px){input,select{font-size:16px}.grid{grid-template-columns:1fr}h1{font-size:28px}.kv div{flex-direction:column;gap:2px}}
</style></head>
<body><main>
<div class="top"><h1>Attack lab: make Invoice Leash pay</h1><a href="./">← the recorded runs</a></div>
<div class="card" style="border-color:var(--acc);margin-bottom:14px"><b>Start here (two clicks):</b> <a href="#v4">§7, the live InvoiceDeskV4</a>. Press "As the agent: classical key only" and the live desk answers <code>BadAgentSignature</code>, what a key derived after Q-Day gets; press "As the company" and the same invoice would pay.</div>
<p>Then try to break the rest. Pick a real fUSD invoice, change anything, choose who sends it, and ask the <b>legacy InvoiceDeskV2 on the QoreChain testnet</b> (the demo's recorded desk; V4 keeps all its checks) whether it would pay. Your browser sends an <code>eth_call</code> to <code>${data.rpc}</code>; the ML-DSA-87 check is the chain's own precompile. Nothing is sent and nothing is spent, so try as much as you like. You can also <a href="#you">be the vendor</a>: make an ML-DSA-87 key in this tab and sign an invoice yourself, or <a href="#msg">check a company instruction</a>, including a Q-Day forgery.</p>
<p class="live"><span class="dot" id="dot"></span><span id="live">connecting to qorechain-diana…</span></p>

<div class="card" style="font-size:14px;margin-bottom:18px"><b>Which desk is which.</b> §1–5 and the lists at the end use <b>InvoiceDeskV2</b>, the demo's recorded desk (<a href="https://explore.qore.network/address/${data.desk}">${data.desk.slice(0, 10)}…</a>). §6 is an ordinary account. §7 asks <b>InvoiceDeskV4</b>, the live agent's desk now (<a href="https://explore.qore.network/address/${json("runs/live/desk.json").v2.invoiceDesk}">${json("runs/live/desk.json").v2.invoiceDesk.slice(0, 10)}…</a>). V3 and V4 keep V2's checks and add per-vendor invoice ids and late settlement (V3) and the agent's own ML-DSA-87 signature (V4).</div>

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

<h2 id="you">4. Be the vendor: sign it yourself, with a post-quantum key made in this tab</h2>
<div class="card you">
<p style="margin-top:0">Your browser makes a fresh <b>ML-DSA-87</b> key (FIPS 204, the scheme QoreChain's precompile checks) and signs the invoice in step 2, field for field. The key lives only in this tab: it is not saved, not sent, and not registered on chain. Then ask the chain as before.</p>
<div class="btns"><button type="button" class="main" id="mkkey">1. Make my ML-DSA-87 key</button><button type="button" class="main" id="signme" disabled>2. Sign the invoice above with it</button></div>
<div class="kv" id="mykey" style="margin-top:10px"></div>
<p class="dim" style="font-size:14px;margin-bottom:0">What to expect: your signature is mathematically valid (your browser checks it against your own public key), yet the desk refuses it. With Hostline or Tokenwell as payee it reads <i>their</i> registered key, and your signature does not match it: <code>BadSignature</code>. With Mallory as payee: <code>UnknownVendor</code>. A valid post-quantum signature is not enough; it has to be the payee's, and the payee has to be one the company approved.</p>
</div>

<h2 id="msg">5. "Approved by the CFO": instructions the agent may trust, checked in your browser</h2>
<div class="card you">
<p style="margin-top:0">The company signs instructions to its agent as <b>QoreSign</b> messages (the format QoreX's <code>signArbitrary</code> makes): secp256k1 plus <b>ML-DSA-87</b> over <code>"qorechain-msg-v1|qorechain-diana|" + text</code>. Pick one; your browser reads the company's registered ML-DSA-87 key from the chain (precompile <code>0x…0a02</code>) and verifies the post-quantum half itself. The <b>Q-Day forgery</b> carries a valid signature from the company's classical key (as if a quantum computer had broken it) and an ML-DSA-87 signature from another key. Edit the text and check again.</p>
<div class="presets" id="msgs"></div>
<label for="msgtext">Message text</label><textarea id="msgtext" rows="3" style="width:100%;font:inherit"></textarea>
<div class="btns"><button type="button" class="main" id="msgcheck">Check the ML-DSA-87 signature</button></div>
<div class="local" id="msgout">Pick a message.</div>
<div style="border-top:1px solid var(--line);margin-top:14px;padding-top:12px">
<p style="margin:0 0 6px"><b>Sign one yourself with QoreX.</b> If you have the QoreX wallet (testnet, with your ML-DSA-87 key registered), sign the text above with <code>signArbitrary</code>. Your browser then reads <i>your</i> key from the chain and checks the ML-DSA-87 half. Edit one character and check again: it fails.</p>
<div class="btns"><button type="button" class="main" id="qxsign">Sign the text with QoreX</button><button type="button" id="qxcheck" disabled>Check my signature against the text</button></div>
<div class="local" id="qxout">QoreX: not connected.</div>
</div>
<p class="dim" style="font-size:14px;margin-bottom:0">The classical half is checked too, by <code>npm run verify</code> and the MCP tool <code>verify_message</code> (QoreSign's <code>verifyMessageWithChain</code>). After Q-Day only the ML-DSA-87 half means anything, and that is the half shown here.</p>
</div>

<h2 id="shor">6. Shor's gift: this account's private key is public. Take its QOR.</h2>
<div class="card you">
<p style="margin-top:0">Pretend Q-Day has come: a quantum computer has broken this account's <b>secp256k1</b> key. We publish it below, so you hold it too. The account holds about 5 QOR. Its <b>ML-DSA-87</b> key is registered on chain and is <i>not</i> published. Your browser signs an ordinary Ethereum transaction with the public key and sends it to the testnet.</p>
<div class="kv" id="pubstate"><span class="dim">reading…</span></div>
<label for="pubto">Send to (any 0x address, yours if you like)</label><input id="pubto">
<label for="pubamt">QOR</label><input id="pubamt" value="4">
<div class="btns"><button type="button" class="main" id="pubgo">Sign with the published key and send</button></div>
<div class="local" id="pubout">Nothing sent yet.</div>
<p class="dim" style="font-size:14px;margin-bottom:0">What to expect: the chain refuses it (<i>no open EVM authorisation window</i>). A classical signature alone is accepted only inside a window, and only the account's ML-DSA-87 key can open one. On the Cosmos side, a <code>MsgSend</code> signed with this key gets code 20 (<i>must include</i> the ML-DSA-87 signature): <code>node scripts/qday-public.mjs attack</code>. <code>npm run verify</code> checks every day that the QOR is still there and that the account has executed nothing but its own key registration.</p>
</div>

<h2 id="v4">7. After Q-Day: the agent's classical key alone, against the real InvoiceDeskV4</h2>
<div class="card you">
<p style="margin-top:0">QoreChain links an agent's key as ed25519 or secp256k1, so a quantum computer could derive it from its public key. On <b>InvoiceDeskV4</b>, the live agent's desk, that key is not enough: every agent payment must also carry the agent's own <b>ML-DSA-87</b> signature over this exact invoice, checked by the precompile against the signer the company named. Ask the real desk about a genuine, unpaid invoice (Daily Hosting Co, 3 fUSD), as the agent's account:</p>
<div class="btns"><button type="button" class="main" id="v4-none">As the agent: classical key only</button><button type="button" id="v4-mine">As the agent: an ML-DSA-87 signature from a key made here</button><button type="button" id="v4-company">As the company, in person</button></div>
<div class="local" id="v4out">Nothing asked yet.</div>
<p class="dim" style="font-size:14px;margin-bottom:0">With the real signer's ML-DSA-87 signature, the agent does pay: the same kind of invoice, live, refused without the signature (<a id="v4ref">tx</a>) and paid with it (<a id="v4paid">tx</a>).</p>
</div>

<h2>The company's leash on its agent, read live</h2>
<div class="card kv" id="state"><span class="dim">reading…</span></div>

<h2>What the agent's key cannot even send</h2>
<div class="card"><p class="dim" style="margin-top:0">The agent's own account holds no fUSD, its QoreChain rule lists no QOR and no fUSD, and it may make one call: <code>InvoiceDeskV2.pay</code>. These need the agent's key, so they are recorded rather than tried here; every one is refused by the chain:</p><ol class="log" id="refusals"></ol></div>
<p class="dim" style="margin-top:32px;font-size:14px">InvoiceDeskV2 <a href="https://explore.qore.network/address/${data.desk}">${data.desk}</a> · qorechain-diana · <a href="lab-v1.html">v1 lab (QOR)</a> · <a href="https://github.com/eltociear/invoice-leash">code</a> · ABI encoding by <a href="https://github.com/ethers-io/ethers.js">ethers.js</a> (MIT) and ML-DSA-87 by <a href="https://github.com/paulmillr/noble-post-quantum">noble-post-quantum</a> (MIT), both served from this site.</p>
</main>
<script src="vendor/ethers.umd.min.js"></script>
<script type="module">import { ml_dsa87 } from "./vendor/mldsa87.min.js"; window.mldsa = ml_dsa87; document.dispatchEvent(new Event("mldsa"));</script>
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
let base, cur, me = null;
const DOMAIN = E.keccak256(E.toUtf8Bytes("LEASH-INVOICE-v2"));
// The exact bytes the vendor signs and InvoiceDeskV2 verifies (contracts/InvoiceDeskV2.sol, lib/invoices.mjs invoiceMessageV2).
const message = (c, amount) => E.getBytes(E.AbiCoder.defaultAbiCoder().encode(["bytes32","uint256","address","address","address","address","uint256","bytes32","uint64"],
  [DOMAIN, 9800, D.desk, c.payer, c.vendor, c.token, amount, E.keccak256(E.toUtf8Bytes(c.ref)), c.dueBy]));
const pqcKey = async (a) => { const r = await rpc("eth_call", [{ to: "0x0000000000000000000000000000000000000a02", data: status.encodeFunctionData("pqcKeyStatus", [a]) }, "latest"]); return status.decodeFunctionResult("pqcKeyStatus", r.result); };
const vfy = (pk, msg, sig) => { try { return window.mldsa.verify(E.getBytes(sig), msg, E.getBytes(pk)); } catch { return false; } };
// the testnet RPC, retried on a network failure (a blip must not leave the page broken); any answer marks the page live
async function rpc(method, params) {
  for (let i = 0; ; i++) {
    try {
      const r = await fetch(D.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }) });
      if (!r.ok) throw new Error("the testnet RPC answered HTTP " + r.status);
      const j = await r.json(); markLive(); return j;
    } catch (e) { if (i >= 3 || !(e instanceof TypeError)) throw e; await new Promise((res) => setTimeout(res, 1000 * 2 ** i)); }
  }
}
let liveShown = false;
function markLive() { if (liveShown) return; liveShown = true; $("dot").classList.add("on"); fetch(D.rpc, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_blockNumber", params: [] }) }).then((r) => r.json()).then((r) => { $("live").textContent = "live: qorechain-diana, block " + parseInt(r.result, 16).toLocaleString(); }).catch(() => { $("live").textContent = "live: qorechain-diana"; }); }
// a first read that fails offers a retry instead of a dead end
function load(id, fn) { fn().catch((e) => { $(id).innerHTML = "could not read the chain: " + h(e.message) + ' <a href="#" data-retry>retry</a>'; $(id).querySelector("[data-retry]").onclick = (ev) => { ev.preventDefault(); $(id).textContent = "reading the chain\u2026"; load(id, fn); }; }); }
const h = (x) => String(x ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const noPQ = () => new Promise((r, j) => { if (window.mldsa) return r(); document.addEventListener("mldsa", r, { once: true }); setTimeout(() => j(new Error("the ML-DSA-87 module did not load")), 15000); });
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
  const s = cur.signature; $("sig").textContent = (s.length - 2) / 2 + " bytes · " + s.slice(0, 26) + "…" + s.slice(-16) + (me && s === me.sig ? "  (signed by your key)" : s !== base.signature ? "  (tampered)" : "");
}
function changes() {
  const c = []; const L = { payer: "payer", vendor: "payee", token: "currency", amount: "amount", ref: "invoice number" };
  for (const k in L) if (String(cur[k]) !== String(base[k])) c.push(L[k]);
  if (cur.dueBy !== base.dueBy) c.push("due date"); if (cur.signature !== base.signature) c.push("signature");
  return c;
}
async function ask() {
  try { await ask1(); } catch (e) { $("out").innerHTML = '<h2 style="margin-top:0">3. The chain’s answer</h2><p class="verdict no">Could not reach the testnet</p><p class="why">' + h(e.message) + " Try again in a moment.</p>"; } finally { $("go").disabled = false; }
}
async function ask1() {
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
        ? 'The agent’s account cannot send that QOR: it holds almost none, and its chain rule allows no QOR at all (<a href="' + D.chainRefusals[1][2] + '">denom uqor not allowed</a>). Ask as the company to see the signature check: the currency is signed.'
        : "The sender's balance is lower than the QOR sent with the call.";
    }
    else { title = "Error"; why = h(res.error?.message ?? "no answer"); }
  }
  const c = changes();
  $("out").innerHTML = '<h2 style="margin-top:0">3. The chain\\'s answer</h2><p class="verdict ' + (ok ? "ok" : "no") + '">' + title + '</p><p class="why">' + why + "</p>" +
    (c.length ? '<p class="diff">You changed: ' + c.join(", ") + "</p>" : '<p class="dim" style="font-size:14px">No changes from the preset.</p>') +
    '<p class="dim" style="font-size:13px;margin-top:12px">eth_call from ' + (D.senders[cur.sender] ?? cur.sender) + " · block " + parseInt(blk.result, 16).toLocaleString() + " · " + ms + " ms · " + cur.amount + " " + unit(cur.token) + " to " + h(name(cur.vendor)) + "</p>" +
    '<div class="local" id="local">Checking the signature in your browser too…</div>';
  local(amount).catch((e) => { $("local").textContent = "Local check unavailable: " + e.message; });
}
// Independently of the chain: fetch the payee's registered ML-DSA-87 public key (precompile 0x…0a02) and verify here.
async function local(amount) {
  await noPQ();
  const msg = message(cur, amount), [reg, , pk] = await pqcKey(cur.vendor);
  const t0 = performance.now(), theirs = reg && vfy(pk, msg, cur.signature), ms = Math.round(performance.now() - t0);
  let h = "<b>Your browser</b>, with " + name(cur.vendor) + "'s public key read from the chain (" + (pk.length - 2) / 2 + " bytes): the ML-DSA-87 signature over these " + msg.length + " bytes is " +
    (theirs ? '<b class="ok">valid</b>' : '<b class="no">not valid</b>') + " (" + ms + " ms, noble-post-quantum).";
  if (me && cur.signature === me.sig) h += "<br>With <b>your</b> key from step 4 the same signature is " + (vfy(me.pk, msg, cur.signature) ? '<b class="ok">valid</b>' : '<b class="no">not valid</b>') + ". Valid, but not the payee's.";
  $("local").innerHTML = h;
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
let msg = null;
$("msgs").innerHTML = D.messages.map((m, i) => '<button type="button" data-i="' + i + '">' + h(m.name) + "</button>").join("");
document.querySelectorAll("#msgs button").forEach((b) => b.onclick = () => { msg = D.messages[Number(b.dataset.i)]; $("msgtext").value = msg.text; document.querySelectorAll("#msgs button").forEach((x) => x.setAttribute("aria-pressed", x === b)); $("msgout").textContent = "Ready: check it."; });
// QoreX (FAQ: window.qorex.native, signArbitrary in QoreSign message-signing-v1 format). bech32 -> 0x for the precompile.
const B32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const qorToHex = (a) => { const d = a.slice(a.lastIndexOf("1") + 1, -6).split("").map((c) => B32.indexOf(c)); let acc = 0, bits = 0; const out = []; for (const v of d) { acc = (acc << 5) | v; bits += 5; while (bits >= 8) { bits -= 8; out.push((acc >> bits) & 255); } } return E.getAddress(E.hexlify(Uint8Array.from(out.slice(0, 20)))); };
let qx = null;
$("qxsign").onclick = async () => {
  const q = window.qorex?.native;
  if (!q) { $("qxout").textContent = "QoreX was not found in this browser. Install the QoreX extension (or open this page in the QoreX app's browser) and switch it to testnet."; return; }
  try {
    if (Array.isArray(q.capabilities) && !q.capabilities.includes("signArbitrary")) throw new Error("this QoreX version has no signArbitrary");
    await q.enable("qorechain-diana");
    const { bech32Address } = await q.getKey("qorechain-diana");
    const text = $("msgtext").value || "Invoice Leash: a message signed with my QoreX ML-DSA-87 key.";
    if (!$("msgtext").value) $("msgtext").value = text;
    const sig = await q.signArbitrary("qorechain-diana", bech32Address, text);
    qx = { signer: bech32Address, text, sig };
    $("qxcheck").disabled = false;
    $("qxout").textContent = "Signed by " + bech32Address + ". Now check it (and try again after editing the text).";
  } catch (e) { $("qxout").textContent = "QoreX: " + (e?.message ?? e); }
};
$("qxcheck").onclick = async () => {
  try {
    await noPQ();
    const pqB64 = qx.sig?.pq?.signature ?? qx.sig?.pqSignature;
    if (!pqB64) throw new Error("the signature has no ML-DSA-87 part (is your ML-DSA-87 key registered?)");
    const [reg, alg, pk, proven] = await pqcKey(qorToHex(qx.signer));
    const text = $("msgtext").value, bytes = E.toUtf8Bytes("qorechain-msg-v1|qorechain-diana|" + text);
    const ok = reg && Number(alg) === 1 && vfy(pk, bytes, Uint8Array.from(atob(pqB64), (c) => c.charCodeAt(0)));
    let wallet = "";
    try { if (window.qorex?.native?.verifyArbitrary) wallet = " QoreX's own verifyArbitrary says: " + ((await window.qorex.native.verifyArbitrary("qorechain-diana", qx.signer, text, qx.sig)) ? "valid" : "not valid") + "."; } catch { /* optional */ }
    $("qxout").innerHTML = "Your key on chain: " + (reg ? (pk.length - 2) / 2 + " bytes" + (proven ? ", possession proven" : "") : "none registered") + ". The ML-DSA-87 half over the text " + (text === qx.text ? "you signed" : "<b>as edited</b>") + ": " +
      (ok ? '<b class="ok">AUTHENTIC</b>' : '<b class="no">NOT AUTHENTIC</b>') + "." + h(wallet);
  } catch (e) { $("qxout").textContent = "Could not check: " + e.message; }
};
$("msgcheck").onclick = async () => {
  if (!msg) return;
  try {
    await noPQ();
    const [reg, alg, pk, proven] = await pqcKey(msg.signerEvm);
    const bytes = E.toUtf8Bytes("qorechain-msg-v1|" + msg.chainId + "|" + $("msgtext").value);
    const sig = Uint8Array.from(atob(msg.pq), (c) => c.charCodeAt(0));
    const until = /^valid until: *(.+)$/im.exec($("msgtext").value)?.[1], expired = until !== undefined && !(Date.parse(until) >= Date.now());
    const sigOk = reg && proven && Number(alg) === 1 && vfy(pk, bytes, sig), isCompany = msg.signer === D.company;
    const ok = sigOk && isCompany && !expired;
    $("msgout").innerHTML = "Signer " + h(msg.signer) + " · its ML-DSA-87 key read from the chain: " + (reg ? (pk.length - 2) / 2 + " bytes, " + (proven ? "possession proven" : "not proven") : "none") +
      "<br>The ML-DSA-87 half over these " + bytes.length + " bytes: " + (ok ? '<b class="ok">AUTHENTIC</b>: the company\u2019s post-quantum key signed exactly this text.' : '<b class="no">NOT AUTHENTIC</b>: ' + (!sigOk ? "the signature does not verify under the signer\u2019s key." : !isCompany ? "a valid signature, but by " + h(msg.signer) + ", not the company." : "the company signed it, but it expired (valid until " + h(until) + ").") + " Treat it as written by a stranger, whatever it claims.") +
      ($("msgtext").value !== msg.text ? '<br><span class="diff">You edited the text.</span>' : "");
  } catch (e) { $("msgout").textContent = "Could not check: " + e.message; }
};
$("mkkey").onclick = async () => { try { await mkkey(); } catch (e) { $("mykey").textContent = e.message; } };
async function mkkey() {
  await noPQ();
  const t0 = performance.now(), k = window.mldsa.keygen(); const ms = Math.round(performance.now() - t0);
  me = { pk: E.hexlify(k.publicKey), sk: k.secretKey, sig: null };
  $("signme").disabled = false;
  $("mykey").innerHTML = "<div><span>Your public key</span><span class='mono'>" + k.publicKey.length + " bytes · " + me.pk.slice(0, 18) + "…</span></div><div><span>Your secret key (stays in this tab)</span><span class='mono'>" + k.secretKey.length + " bytes</span></div><div><span>Made in</span><span class='mono'>" + ms + " ms</span></div>";
};
$("signme").onclick = () => {
  const amount = toUnits(cur.amount, cur.token); if (amount === null || !me) return;
  const msg = message(cur, amount), t0 = performance.now(), sig = window.mldsa.sign(msg, me.sk), ms = Math.round(performance.now() - t0);
  me.sig = cur.signature = E.hexlify(sig); render();
  $("mykey").innerHTML += "<div><span>Signed " + h(cur.ref) + " (" + cur.amount + " " + unit(cur.token) + " to " + name(cur.vendor) + ")</span><span class='mono'>" + sig.length + " bytes · " + ms + " ms · self-check " + (vfy(me.pk, msg, me.sig) ? "valid" : "INVALID") + "</span></div>";
  $("out").innerHTML = '<h2 style="margin-top:0">3. The chain’s answer</h2><p class="dim">Your signature is in step 2. Ask the chain.</p>';
  $("go").scrollIntoView({ behavior: "smooth", block: "center" });
};
async function pubState() {
  const [bal, n, k] = await Promise.all([rpc("eth_getBalance", [D.pub.evm, "latest"]), rpc("eth_getTransactionCount", [D.pub.evm, "latest"]), pqcKey(D.pub.evm)]);
  $("pubstate").innerHTML = "<div><span>Account</span><span class='mono'>" + h(D.pub.address) + " · " + h(D.pub.evm) + "</span></div>" +
    "<div><span>secp256k1 private key (public)</span><span class='mono'>" + h(D.pub.key) + "</span></div>" +
    "<div><span>Balance, live</span><span class='mono'>" + E.formatEther(BigInt(bal.result)) + " QOR</span></div>" +
    "<div><span>ML-DSA-87 key on chain</span><span class='mono'>" + (k[0] ? (k[2].length - 2) / 2 + " bytes, possession " + (k[3] ? "proven" : "not proven") : "none") + " (secret key not published)</span></div>" +
    "<div><span>Transactions it has executed</span><span class='mono'>" + parseInt(n.result, 16) + " (its own key registration)</span></div>";
}
$("pubto").value = D.attacker;
$("pubgo").onclick = async () => {
  $("pubgo").disabled = true; $("pubout").textContent = "Signing with the published key…";
  try {
    const to = E.getAddress($("pubto").value.trim()), value = E.parseEther($("pubamt").value.trim() || "0");
    const [n, gp] = await Promise.all([rpc("eth_getTransactionCount", [D.pub.evm, "pending"]), rpc("eth_gasPrice", [])]);
    const raw = await new E.Wallet(D.pub.key).signTransaction({ type: 0, chainId: 9800, nonce: parseInt(n.result, 16), gasPrice: BigInt(gp.result), gasLimit: 21000, to, value });
    const r = await rpc("eth_sendRawTransaction", [raw]);
    $("pubout").innerHTML = "Signed: a valid secp256k1 signature by the account's own key (" + (raw.length / 2 - 1) + "-byte transaction).<br>" + (r.error
      ? '<b class="ok">REFUSED by the chain</b>: ' + h(r.error.message.split(" [")[0])
      : '<b class="no">ACCEPTED</b> (transaction ' + h(r.result) + "). That would be news: please open an issue.");
  } catch (e) { $("pubout").textContent = "Could not send: " + e.message; }
  finally { $("pubgo").disabled = false; pubState().catch(() => {}); }
};
load("pubstate", pubState);
// §7: InvoiceDeskV4, asked as the agent without (or with a wrong) ML-DSA-87 signature, and as the company
const desk4 = new E.Interface(["function pay(address,address,address,uint256,bytes32,uint64,bytes,bytes) payable",
  "error NotPayersAgent(address)", "error AgentSignerNotSet(address)", "error AgentKeyNotProven(address)", "error BadAgentSignature()", "error UnknownVendor(address)", "error BadSignature()", "error AlreadyPaid(bytes32)", "error PastDue(uint64)", "error OverPerPaymentLimit(uint256,uint256)", "error OverDailyLimit(uint256,uint256,uint256)", "error TransferFailed()", "error ZeroAmount()", "error WrongAmount(uint256,uint256)", "error AgentCannotPayNative()", "error VendorKeyNotProven(address)"]);
$("v4ref").href = D.v4.refusedLink; $("v4paid").href = D.v4.paidLink;
const v4ask = async (label, from, agentSig) => {
  const i = D.v4.inv;
  const r = await rpc("eth_call", [{ from, to: D.v4.desk, data: desk4.encodeFunctionData("pay", [D.v4.payer, i.token, i.vendor, i.amount, i.id, i.dueBy, i.signature, agentSig]) }, "latest"]);
  let v = "WOULD PAY"; if (r.error) { try { v = desk4.parseError(r.error.data).name; } catch { v = r.error.message; } }
  $("v4out").innerHTML = ($("v4out").textContent === "Nothing asked yet." ? "" : $("v4out").innerHTML + "<br>") + h(label) + ": " + (v === "WOULD PAY" ? '<b class="ok">WOULD PAY</b>' : '<b class="no">' + h(v) + "</b>");
};
$("v4-none").onclick = () => v4ask("as the agent, classical key only", D.v4.agent, "0x").catch((e) => { $("v4out").textContent = e.message; });
$("v4-mine").onclick = async () => {
  try {
    await noPQ();
    const i = D.v4.inv, k = window.mldsa.keygen();
    const m = E.getBytes(E.AbiCoder.defaultAbiCoder().encode(["bytes32", "uint256", "address", "address", "address", "address", "address", "uint256", "bytes32"],
      [E.keccak256(E.toUtf8Bytes("LEASH-AGENT-PAY-v1")), 9800, D.v4.desk, D.v4.payer, D.v4.agent, i.vendor, i.token, i.amount, i.id]));
    await v4ask("as the agent, a valid ML-DSA-87 signature by a key made in this tab (not the named signer's)", D.v4.agent, E.hexlify(window.mldsa.sign(m, k.secretKey)));
  } catch (e) { $("v4out").textContent = e.message; }
};
$("v4-company").onclick = () => v4ask("as the company, in person (no agent signature needed)", D.v4.payer, "0x").catch((e) => { $("v4out").textContent = e.message; });
load(D.presets[0]);
rpc("eth_blockNumber", []).catch(() => { if (!liveShown) $("live").textContent = "could not reach the testnet RPC yet (each button retries)"; });
load("state", state);
</script>
</body></html>
`;
mkdirSync(new URL("docs/vendor/", root), { recursive: true });
copyFileSync(new URL("node_modules/ethers/dist/ethers.umd.min.js", root), new URL("docs/vendor/ethers.umd.min.js", root));
copyFileSync(new URL("node_modules/ethers/LICENSE.md", root), new URL("docs/vendor/ethers-LICENSE.md", root));
// docs/vendor/mldsa87.min.js: npx esbuild@0.24.0 scripts/vendor-src/mldsa.mjs --bundle --format=esm --minify (noble-post-quantum, pinned in package-lock)
copyFileSync(new URL("node_modules/@noble/post-quantum/LICENSE", root), new URL("docs/vendor/noble-post-quantum-LICENSE", root));
writeFileSync(new URL("docs/lab.html", root), html);
console.log(`docs/lab.html: ${data.presets.length} presets (v2, fUSD), ${(html.length / 1024).toFixed(0)} KB`);
