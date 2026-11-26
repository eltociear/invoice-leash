// Every agent ML-DSA-87 signature ever made public, asked again: could the agent's classical key alone get
// any of them paid now?
//
// An InvoiceDeskV4 agent signature binds one invoice (desk, payer, agent, vendor, token, amount, id) and has
// no expiry of its own. Sent with a payment the desk refused for a reason that can pass later (over today's
// limit, say), it stays valid until the invoice is paid or past due, and it is public: in the relaying
// transaction's calldata, or in a record in this repository. So this script collects them all:
//   - every pay() relayed for an agent to an InvoiceDeskV4 (MsgExecuteEVM): all its fee wallet sent, and every
//     refused one whoever relayed it, read from REST
//   - every pay() an agent account sent itself on the EVM lane (its MsgEthereumTx, found through REST)
//   - every pay() calldata stored in this repository (runs/**/*.json, docs/*.json)
// and dry-runs each as that agent (eth_call): it costs nothing and changes nothing.
//   node scripts/signature-sweep.mjs              writes runs/signature-sweep.json; exits 1 if any would pay
//   node scripts/signature-sweep.mjs --invoices <dir>   also writes each one that would pay as an invoice file,
//                                                       for the company to settle in person (desk.mjs pay)
import { readFileSync, readdirSync, statSync, writeFileSync, mkdirSync } from "node:fs";
import { Interface, JsonRpcProvider, getAddress, keccak256 } from "ethers";

const ROOT = new URL("../", import.meta.url);
const REST = process.env.QORE_REST ?? "https://api-testnet.qore.host";
const provider = new JsonRpcProvider(process.env.QORE_EVM_RPC ?? "https://evm-testnet.qore.host", 9800, { staticNetwork: true });
const desk = new Interface(JSON.parse(readFileSync(new URL("build/InvoiceDeskV4.json", ROOT), "utf8")).abi);
const SEL = desk.getFunction("pay").selector;
const json = (p) => JSON.parse(readFileSync(new URL(p, ROOT), "utf8"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// the testnet's endpoints drop requests now and then: a read is tried again before it counts as an answer
async function retry(fn) { for (let i = 0; ; i++) { try { return await fn(); } catch (e) { if (i >= 4 || e?.data || e?.info?.error?.data) throw e; await sleep(1500 * (i + 1)); } } }
async function get(path) {
  for (let i = 0; ; i++) {
    try { const r = await fetch(REST + path); if (r.ok) return await r.json(); if (r.status === 404) return null; } catch { /* retry */ }
    if (i >= 5) throw new Error(`REST ${path} unavailable`);
    await sleep(1500 * (i + 1));
  }
}

// For one the desk refuses now: can it ever pay? "never", or the one thing the company itself would have to do.
const PQC = new Interface(["function pqcKeyStatus(address) view returns (bool registered, uint8 algorithmId, bytes pubkey, bool possessionProven)", "function pqcVerify(bytes pubkey, bytes signature, bytes message) view returns (bool valid)"]);
const call = async (i, to, fn, args) => i.decodeFunctionResult(fn, await retry(() => provider.call({ to, data: i.encodeFunctionData(fn, args) })));
// The agent's message binds desk, payer, agent, vendor, token, amount and invoice id, NOT the due date or the
// vendor's signature. So a refusal is "never" only if no later invoice with these fields could pass: the agent
// signature itself is void, or this vendor's invoice id is paid (that record never clears), or the fields
// themselves can never be paid by an agent. Otherwise it names who would have to act: the company, or the vendor.
async function later(row, a, d) {
  const due = new Date(row.dueBy * 1000).toISOString().slice(0, 10);
  if (row.now === "PAID") return "now";
  const [payer, token, vendor, amount, id] = a;
  const [named] = await call(desk, d.invoiceDesk, "agentSigner", [payer, row.from]);
  if (!/^0x0{40}$/i.test(named)) {
    const [reg, alg, pk] = await call(PQC, "0x0000000000000000000000000000000000000a02", "pqcKeyStatus", [named]);
    const [m] = await call(desk, d.invoiceDesk, "agentMessage", [payer, row.from, token, vendor, amount, id]);
    const ok = reg && Number(alg) === 1 && (await call(PQC, "0x0000000000000000000000000000000000000a01", "pqcVerify", [pk, a[7], m]))[0];
    if (!ok) return "never: its agent signature does not verify under the signer the desk names (rotated away, or no valid signature); desk.mjs never names a voided signer again";
  }
  if ((await call(desk, d.invoiceDesk, "paid", [payer, vendor, id]))[0]) return "never: this vendor's invoice id is paid, and that record never clears";
  if (amount === 0n) return "never: zero";
  if (token === "0x0000000000000000000000000000000000000000") return "never: an agent may not pay native QOR";
  if (row.now === "NotPayersAgent") return /^0x0{40}$/i.test(named) ? `only if the company makes ${row.from} an agent and names this signer for it` : `only if the company switches agent ${row.from} on again`;
  if (row.now === "UnknownVendor") {
    const [reg, alg, pk, proven] = await call(PQC, "0x0000000000000000000000000000000000000a02", "pqcKeyStatus", [vendor]);
    if (!reg || !proven || Number(alg) !== 1) return `only if ${vendor} registers an ML-DSA-87 key, signs these fields, and the company approves it`;
    return `only if the company approves vendor ${vendor}`;
  }
  if (row.now === "BadSignature") return `only if vendor ${vendor} signs an invoice with this id, token and amount (any due date)`;
  if (row.now === "PastDue" || row.dueBy * 1000 < Date.now()) return `only if vendor ${vendor} reissues this invoice id with a later due date`;
  if (row.now === "OverPerPaymentLimit") return `only if the company raises the agent's per-payment limit to ${Number(amount) / 1e6} fUSD`;
  if (row.now === "OverDailyLimit") return `on a later day: today's limit is used (due ${due})`;
  return `unclassified: ${row.now}`;
}

export async function sweep() {
const desks = ["runs/live/desk.json", "runs/own-company-v4/desk.json"].map((p) => ({ record: p, ...json(p).v2 })).filter((d) => d.version === 4);
const byDesk = new Map(desks.map((d) => [getAddress(d.invoiceDesk), d]));
const found = new Map(); // one entry per (desk, calldata)
const add = (deskAddr, from, data, where) => {
  const d = byDesk.get(getAddress(deskAddr));
  if (!d || !data.startsWith(SEL)) return;
  const a = desk.decodeFunctionData("pay", data);
  if (a[7] === "0x") return; // no agent signature: nothing to replay
  const key = `${d.invoiceDesk}|${keccak256(data)}`;
  const e = found.get(key) ?? { desk: d.invoiceDesk, from: getAddress(from), data, where: [] };
  e.where.push(where); found.set(key, e);
};

// 1. relayed: by each desk's fee wallet, and every refused one by ANY relayer. A refused relay names the
//    agent account in its abstractaccount_execution_failed event; a successful one paid its invoice (spent).
//    Not found: a relay by another wallet that failed as a transaction (out of gas, say), which names the
//    agent in no event; such calldata is still in the block, so this is a gap a full indexer would close.
for (const d of desks) for (const query of [`message.sender='${d.gas}'`, `abstractaccount_execution_failed.account='${d.agentAccount}'`]) {
  const q = encodeURIComponent(query);
  for (let page = 1; ; page++) {
    const r = await get(`/cosmos/tx/v1beta1/txs?query=${q}&pagination.limit=100&page=${page}&order_by=ORDER_BY_ASC`);
    const txs = r?.tx_responses ?? [];
    for (const t of txs) for (const m of t.tx.body.messages) {
      if (m["@type"] !== "/qorechain.abstractaccount.v1.MsgExecuteEVM" || m.account !== d.agentAccount) continue;
      if (m.data) add(m.to, d.agentAccountEvm, "0x" + Buffer.from(m.data, "base64").toString("hex"), `tx ${t.txhash}`);
    }
    if (txs.length < 100) break;
  }
}
// 2. the EVM lane: every MsgEthereumTx the agent account itself sent (inside one of its EVM windows), found
//    through its Cosmos transactions, then read as an EVM transaction; plus those the records name
const evmHashes = new Set();
for (const d of desks) {
  const q = encodeURIComponent(`message.sender='${d.agentAccount}'`);
  for (let page = 1; ; page++) {
    const r = await get(`/cosmos/tx/v1beta1/txs?query=${q}&pagination.limit=100&page=${page}&order_by=ORDER_BY_ASC`);
    const txs = r?.tx_responses ?? [];
    for (const t of txs) for (const e of t.events) for (const a of e.attributes) if (a.key === "ethereumTxHash") evmHashes.add(a.value.toLowerCase());
    if (txs.length < 100) break;
  }
}
for (const s of json("runs/probes/window-v4.json").steps) if (/^0x[0-9a-f]{64}$/i.test(s.tx ?? "")) evmHashes.add(s.tx.toLowerCase());
for (const h of evmHashes) {
  const t = await retry(() => provider.getTransaction(h));
  if (t?.to) add(t.to, t.from, t.data, `evm ${h}`);
}
// 3. calldata kept in this repository
const files = (dir) => readdirSync(new URL(dir, ROOT)).flatMap((f) => {
  const p = `${dir}${f}`; return statSync(new URL(p, ROOT)).isDirectory() ? files(`${p}/`) : p.endsWith(".json") ? [p] : [];
});
for (const f of [...files("runs/"), ...files("docs/")]) {
  const walk = (v, ctx) => {
    if (typeof v === "string" && v.startsWith(SEL)) add(ctx.to ?? ctx.desk ?? json(f).desk ?? "", ctx.from ?? byDesk.get(getAddress(ctx.to ?? ctx.desk ?? json(f).desk))?.agentAccountEvm, v, `file ${f}`);
    else if (v && typeof v === "object") for (const x of Object.values(v)) walk(x, Array.isArray(v) ? ctx : { ...ctx, ...v });
  };
  try { walk(json(f), {}); } catch { /* not a desk's calldata */ }
}

// ask each one again, as its agent
async function ask(from, to, data) {
  for (let i = 0; ; i++) {
    try { await provider.call({ from, to, data }); return "PAID"; }
    catch (e) {
      try { const n = desk.parseError(e.data ?? e.info?.error?.data)?.name; if (n) return n; } catch { /* not the desk's */ }
      if (/execution reverted/i.test(e.shortMessage ?? "")) return "Reverted";
      if (i >= 4) throw e;
      await sleep(1500 * (i + 1));
    }
  }
}
const rows = [];
for (const e of found.values()) {
  const a = desk.decodeFunctionData("pay", e.data);
  const row = { desk: e.desk, from: e.from, vendor: a[2], amount: a[3].toString(), id: a[4], dueBy: Number(a[5]), now: await ask(e.from, e.desk, e.data), where: e.where };
  row.later = await later(row, a, byDesk.get(getAddress(e.desk)));
  rows.push(row);
}
return { desks, rows, found, evmLane: evmHashes.size };
}

const isMain = import.meta.url === new URL(`file://${process.argv[1]}`).href;
if (isMain) {
const { desks, rows, found } = await sweep();
const hist = {};
for (const r of rows) hist[r.now] = (hist[r.now] ?? 0) + 1;
const live = rows.filter((r) => r.now === "PAID");
writeFileSync(new URL("runs/signature-sweep.json", ROOT), JSON.stringify({
  what: "every public agent ML-DSA-87 signature on an InvoiceDeskV4 (relayed calldata, EVM-lane calldata, calldata in this repository), dry-run again as its agent: could the agent's classical key alone get it paid now?",
  at: new Date().toISOString(), desks: desks.map((d) => d.invoiceDesk), signatures: rows.length, now: hist, wouldPay: live.length,
  dormant: rows.filter((r) => r.later.startsWith("only") || r.later.startsWith("on a later")).map((r) => ({ id: r.id, amount: r.amount, vendor: r.vendor, later: r.later })), rows }, null, 1) + "\n");
console.log(`${rows.length} public agent signatures on ${desks.length} InvoiceDeskV4 desks; asked again now: ${JSON.stringify(hist)}`);
for (const r of rows.filter((r) => !r.later.startsWith("never") && r.later !== "now")) console.log(`  dormant: ${r.amount} (invoice ${r.id.slice(0, 10)}…): ${r.later}`);
for (const r of live) console.log(`  WOULD PAY: ${r.amount} to ${r.vendor} (invoice ${r.id.slice(0, 10)}…, due ${new Date(r.dueBy * 1000).toISOString().slice(0, 10)}) on ${r.desk}; ${r.where.join(", ")}`);
const out = process.argv.indexOf("--invoices");
if (out > 0 && live.length) {
  const dir = process.argv[out + 1]; mkdirSync(dir, { recursive: true });
  for (const r of live) {
    const a = desk.decodeFunctionData("pay", [...found.values()].find((e) => e.desk === r.desk && desk.decodeFunctionData("pay", e.data)[4] === r.id).data);
    const fusd = (Number(a[3]) / 1e6).toString();
    writeFileSync(`${dir}/${r.id.slice(2, 12)}.json`, JSON.stringify({ subject: "settle in person: an agent signature for this invoice is public (scripts/signature-sweep.mjs)", invoice: { v: 2, token: a[1], vendor: a[2], fusd, amount: a[3].toString(), ref: `SETTLE-${r.id.slice(2, 10)}`, id: a[4], dueBy: Number(a[5]), signature: a[6] } }, null, 1) + "\n");
  }
}
process.exit(live.length ? 1 : 0);
}
