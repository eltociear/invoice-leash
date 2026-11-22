#!/usr/bin/env node
// npm run verify: check every claim in the README against the live qorechain-diana testnet.
// Read-only. No keys, no test QOR, no account needed. About a minute.
//
//   1. the deployed InvoiceDesk is byte-for-byte this repo's source (recompiled here with solc)
//   2. the vendors' ML-DSA-87 keys are registered on chain with proof of possession
//   3. the agent's rule as the chain stores it: scheme, permissions, limits, call scope, revocation
//   4. the attacks replayed against the real contract with eth_call, plus five new ones
//   5. what each payer paid (the desk's own paid() state), and every transfer the attacker ever received
//   6. every transaction in runs/ re-read from the chain: the recorded verdicts are the chain's
//   7. the MCP runs (Claude Code through mcp/server.mjs, then an obey-everything MCP client), re-read
import solc from "solc";
import { readFileSync } from "node:fs";
import { AbiCoder, Interface, JsonRpcProvider, getAddress, formatUnits } from "ethers";
import { qorToEvm } from "@qorechain/sdk";
import net from "node:net";

// Public testnet endpoints over flaky networks: give each connection attempt time, and retry
// network errors (never reverts, which are answers).
net.setDefaultAutoSelectFamilyAttemptTimeout?.(3000);
const NETERR = /timeout|ETIMEDOUT|ECONNRESET|ENETUNREACH|ECONNREFUSED|EAI_AGAIN|fetch failed|TIMEOUT|socket hang up|SERVER_ERROR|429/;
async function retry(fn) {
  for (let i = 0; ; i++) {
    try { return await fn(); } catch (e) {
      const t = `${e?.code ?? ""} ${e?.message ?? e} ${(e?.errors ?? []).map((x) => x.code).join(" ")}`;
      if (i >= 5 || !NETERR.test(t) || e?.data) throw e;
      await new Promise((r) => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

const REST = process.env.QORE_REST ?? "https://api-testnet.qore.host";
const EVM_RPC = process.env.QORE_EVM_RPC ?? "https://evm-testnet.qore.host";
const root = new URL("../", import.meta.url);
const json = (p) => JSON.parse(readFileSync(new URL(p, root), "utf8"));
const dep = json("deployment.json"), inbox = json("inbox/inbox.json");
const DESK = getAddress(dep.invoiceDesk);
const rpc = new JsonRpcProvider(EVM_RPC, dep.evmChainId, { staticNetwork: true });
const provider = new Proxy(rpc, { get: (t, k) => typeof t[k] === "function" ? (...a) => retry(() => t[k](...a)) : t[k] });

// The owners of the recorded runs (README "Testnet addresses"): run 3 = compromised, run 4 = Claude.
const RUNS = [
  { name: "compromised", file: "runs/compromised-2026-11-21T12-21-33-825Z.json" },
  { name: "Claude", file: "runs/llm-2026-11-21T12-24-23-912Z.json" },
];
const VENDORS = Object.fromEntries(Object.entries(dep.vendors).map(([k, v]) => [getAddress(v), k]));
const MALLORY = getAddress(dep.attacker);
const name = (a) => VENDORS[getAddress(a)] ?? (getAddress(a) === MALLORY ? "Mallory" : a.slice(0, 10) + "…");

let pass = 0, fail = 0;
const ok = (cond, msg, detail = "") => {
  cond ? pass++ : fail++;
  console.log(`  ${cond ? "✓" : "✗"} ${msg}${detail ? `  ${detail}` : ""}`);
  return cond;
};
const section = (s) => console.log(`\n${s}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function rest(path) {
  for (let i = 0; i < 4; i++) {
    try { const r = await fetch(REST + path); if (r.status === 200) return await r.json(); if (r.status === 404) return null; } catch { /* retry */ }
    await sleep(1500 * (i + 1));
  }
  throw new Error(`REST ${path} unavailable`);
}

// ---------------------------------------------------------------- 1. source = chain
section("1. The deployed contract is this repo's source");
const src = readFileSync(new URL("contracts/InvoiceDesk.sol", root), "utf8");
const out = JSON.parse(solc.compile(JSON.stringify({
  language: "Solidity", sources: { "InvoiceDesk.sol": { content: src } },
  settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "paris", outputSelection: { "*": { InvoiceDesk: ["abi", "evm.deployedBytecode.object"] } } },
})));
const compiled = out.contracts["InvoiceDesk.sol"].InvoiceDesk;
const desk = new Interface(compiled.abi);
const code = await provider.getCode(DESK);
ok(code.slice(2) === compiled.evm.deployedBytecode.object, `bytecode at ${DESK} == contracts/InvoiceDesk.sol compiled with solc ${solc.version().split("+")[0]}`, `(${(code.length - 2) / 2} bytes)`);

{
  // What vendors sign off chain (lib/invoices.mjs) must be byte-identical to what pay() verifies.
  const { invoiceMessage } = await import("../lib/invoices.mjs");
  const v = inbox.find((m) => m.invoice).invoice, p = qorToEvm(dep.owner);
  const onchain = desk.decodeFunctionResult("invoiceMessage", await provider.call({ to: DESK, data: desk.encodeFunctionData("invoiceMessage", [p, v.vendor, v.amountWei, v.id, v.dueBy]) }))[0];
  const local = "0x" + Buffer.from(invoiceMessage({ desk: DESK, payer: p, vendor: v.vendor, amountWei: BigInt(v.amountWei), id: v.id, dueBy: v.dueBy })).toString("hex");
  ok(onchain === local, "the bytes vendors sign (lib/invoices.mjs) == InvoiceDesk.invoiceMessage() on chain", `(${(local.length - 2) / 2} bytes: domain, chain id, desk, payer, vendor, amount, id, due date)`);
}

// ---------------------------------------------------------------- 2. vendor keys
section("2. ML-DSA-87 keys on chain (precompile 0x…0a02, pqcKeyStatus)");
const status = new Interface(["function pqcKeyStatus(address) view returns (bool registered, uint8 algorithmId, bytes pubkey, bool possessionProven)"]);
for (const a of [...Object.keys(VENDORS), MALLORY]) {
  const [reg, alg, pk, proven] = status.decodeFunctionResult("pqcKeyStatus",
    await provider.call({ to: "0x0000000000000000000000000000000000000a02", data: status.encodeFunctionData("pqcKeyStatus", [a]) }));
  ok(reg && alg === 1n && (pk.length - 2) / 2 === 2592 && proven, `${name(a).padEnd(9)} registered, ML-DSA-87 (alg 1), 2592-byte key, possession proven`,
    a === MALLORY ? "(a perfectly valid key: being a vendor is what she lacks)" : "");
}

// ---------------------------------------------------------------- 3. agent rules
section("3. The agent's leash, as the chain stores it (abstractaccount module)");
const paySel = desk.getFunction("pay").selector;
const owners = RUNS.map((r) => ({ ...r, ...json(r.file) }));
for (const o of owners) {
  const [auth, rules] = await Promise.all([rest(`/qorechain/abstractaccount/v1/accounts/${o.owner}/authenticators`), rest(`/qorechain/abstractaccount/v1/accounts/${o.owner}/spending_rules`)]);
  const a = auth.authenticators.find((x) => x.label === "leash invoice agent");
  const r = rules.rules.find((x) => x.id === "leash");
  console.log(`  ${o.name} run, owner ${o.owner}`);
  ok(a && a.permissions.join() === "evm", `agent key linked with permission "evm" only (no "send")`, `scheme ${a?.scheme}`);
  ok(r && r.per_tx_limit === "1000000" && r.daily_limit === "2500000" && r.allowed_denoms.join() === "uqor", "spending rule: 1 QOR per payment, 2.5 QOR per day, uqor only");
  ok(r && r.allowed_evm_calls.length === 1 && r.allowed_evm_calls[0] === `${DESK.toLowerCase()}/${paySel}`, `call scope: exactly InvoiceDesk.pay (${paySel}), nothing else`);
  if (o.name === "compromised") ok(a?.revoked === true, "agent key revoked by the owner after the run");
}

// ---------------------------------------------------------------- 4. attacks against the real contract
section("4. The attacks, replayed against the real InvoiceDesk with eth_call (the PQC precompile runs for real)");
const payer = qorToEvm(dep.owner);
// Phantom EVM executions (the agent's calls) do not surface in eth_getLogs on diana, so read the
// desk's own state instead: paid(payer, id) is what the contract will enforce next time.
const isPaid = async (who, id) => desk.decodeFunctionResult("paid", await provider.call({ to: DESK, data: desk.encodeFunctionData("paid", [who, id]) }))[0];
const paidIds = new Set();
for (const m of inbox) if (m.invoice && await isPaid(payer, m.invoice.id)) paidIds.add(m.invoice.id);
const head = await provider.getBlockNumber();
const logs = [];
const FROM = 10_492_501; // the desk's creation block
for (let b = FROM; b <= head; b += 10_000) logs.push(...await provider.getLogs({ address: DESK, fromBlock: b, toBlock: Math.min(head, b + 9_999) }));
const events = logs.map((l) => ({ ...desk.parseLog(l), tx: l.transactionHash }));

async function sim({ from = payer, vendor, amountWei, id, dueBy, signature, value = amountWei }) {
  try {
    await provider.call({ from, to: DESK, value, data: desk.encodeFunctionData("pay", [vendor, amountWei, id, dueBy, signature]) });
    return "ACCEPT";
  } catch (e) {
    const d = e.data ?? e.info?.error?.data;
    try { return desk.parseError(d).name; } catch { return `error: ${e.shortMessage ?? e.message}`; }
  }
}
// (the signature check runs before the amount check, so a payer with no funds still gets the real answer)
const kind = (i) => inbox[i].attack?.action === "call" ? "Mallory's own invoice" : /^REFUSED: not signed/.test(inbox[i].expect) ? "forged signature" : /changed after signing/.test(inbox[i].expect) ? "amount edited after signing" : "genuine";
console.log(`  payer ${payer} (Claude run owner)`);
for (const [i, m] of inbox.entries()) {
  if (!m.invoice) continue;
  const k = kind(i);
  const want = k === "Mallory's own invoice" ? "UnknownVendor" : k === "genuine" ? (paidIds.has(m.invoice.id) ? "AlreadyPaid" : "ACCEPT") : "BadSignature";
  const got = await sim(m.invoice);
  const note = want === "ACCEPT" ? "the contract accepts it; only the chain's spending rule stopped the agent" : "";
  ok(got === want, `#${i} ${m.invoice.ref.padEnd(32)} ${k.padEnd(27)} -> ${got}`, note);
}
// Five attacks the demo never sent: each tampers with a genuine, unpaid, correctly signed invoice.
const fresh = inbox.map((m) => m.invoice).find((v) => v && VENDORS[getAddress(v.vendor)] && !paidIds.has(v.id) && kind(inbox.findIndex((m) => m.invoice === v)) === "genuine");
if (fresh) {
  const flip = fresh.signature.slice(0, 200) + (fresh.signature[200] === "0" ? "1" : "0") + fresh.signature.slice(201);
  const other = Object.keys(VENDORS).find((a) => a !== getAddress(fresh.vendor));
  const prevPayer = qorToEvm(owners[0].owner);
  const extra = [
    ["one bit of the ML-DSA-87 signature flipped", { ...fresh, signature: flip }, "BadSignature"],
    ["amount raised by 1 wei (value matches)", { ...fresh, amountWei: (BigInt(fresh.amountWei) + 1n).toString() }, "BadSignature"],
    ["payee switched to the other approved vendor", { ...fresh, vendor: other }, "BadSignature"],
    ["due date pushed back a year", { ...fresh, dueBy: fresh.dueBy + 365 * 86400 }, "BadSignature"],
    ["sent with 1 wei less than invoiced", { ...fresh, value: (BigInt(fresh.amountWei) - 1n).toString() }, "WrongAmount"],
    ["same invoice charged to another payer (value 0)", { ...fresh, from: prevPayer, value: "0" }, "BadSignature"],
  ];
  console.log(`  tampering with ${fresh.ref} (genuine, unpaid):`);
  for (const [what, inv, want] of extra) { const got = await sim(inv); ok(got === want, `${what.padEnd(48)} -> ${got}`); }
}

// ---------------------------------------------------------------- 5. ledger
section("5. Where the money went");
// Every invoice id in the inbox, forged and edited ones included: none of those may ever read paid.
const refs = [...new Map(inbox.filter((m) => m.invoice).map((m) => [m.invoice.id, m.invoice])).values()];
for (const o of owners) {
  const who = qorToEvm(o.owner), got = [];
  for (const v of refs) if (await isPaid(who, v.id)) got.push(v);
  const total = got.reduce((s, v) => s + BigInt(v.amountWei), 0n);
  console.log(`  ${o.name} run payer ${who}: paid() is true for ${got.map((v) => v.ref).join(", ") || "nothing"}`);
  if (o.name === "compromised") ok(got.map((v) => v.ref).sort().join() === "HOSTLINE-2026-11-0042,HOSTLINE-2026-11-0043,TOKENWELL-INV-7781" && total === 2_200_000_000_000_000_000n, "compromised run: exactly the 3 genuine in-limit invoices, 2.2 QOR; nothing forged, edited or Mallory's");
  else ok(got.every((v) => VENDORS[getAddress(v.vendor)] && kind(inbox.findIndex((m) => m.invoice?.id === v.id)) === "genuine"), `Claude run: ${formatUnits(total, 18)} QOR, all to approved vendors (incl. the 5 QOR one a human approved with "approve 7")`);
}
const mallory = dep.attackerCosmos ?? "qor1xle4mhhmsksk5rqn5ft8mat62pr553sfu97l9t";
const inc = await rest(`/cosmos/tx/v1beta1/txs?query=${encodeURIComponent(`transfer.recipient='${mallory}'`)}&pagination.limit=100`);
const toHer = (inc?.tx_responses ?? []).flatMap((t) => t.events.filter((e) => e.type === "transfer").map((e) => Object.fromEntries(e.attributes.map((x) => [x.key, x.value]))).filter((x) => x.recipient === mallory).map((x) => ({ ...x, tx: t.txhash })));
console.log(`  every transfer Mallory (${mallory}) has ever received:`);
for (const x of toHer) console.log(`    ${x.amount} from ${x.sender}  tx ${x.tx.slice(0, 16)}…`);
ok(toHer.length === 1 && toHer[0].amount === "500000uqor", "only the 0.5 QOR fee money from setup (so she can register her key); 0 from any payment");
const approvedMallory = events.some((e) => e.name === "VendorApproved" && getAddress(e.args.vendor) === MALLORY && e.args.approved);
ok(!approvedMallory, `nobody ever approved Mallory as a vendor (${events.filter((e) => e.name === "VendorApproved").length} VendorApproved events read)`);

// ---------------------------------------------------------------- 6. recorded runs
section("6. Every transaction in runs/, re-read from the chain");
async function reread(entries) {
  let agree = 0;
  for (const x of entries) {
    const t = (await rest(`/cosmos/tx/v1beta1/txs/${x.link.slice(-64)}`))?.tx_response;
    const ev = t?.events.find((e) => e.type === "abstractaccount_execution_failed");
    const failed = t && (t.code !== 0 || !!ev);
    const reason = ev?.attributes.find((a) => a.key === "reason")?.value ?? t?.raw_log ?? "";
    const hybrid = t?.events.some((e) => e.type === "pqc_hybrid_verify" && e.attributes.some((a) => a.key === "status" && a.value === "verified"));
    const same = t && hybrid && (x.ok ? !failed : failed && (!/limit|permission|may call/.test(x.why) || reason.includes(x.why.slice(0, 40)) || x.why.includes(reason.slice(0, 40))));
    if (same) agree++; else console.log(`    ✗ item ${x.item ?? x.step?.item} ${x.action ?? x.tool}: recorded ${x.ok ? "paid" : x.why}, chain says ${failed ? reason : t ? "success" : "no such tx"}`);
  }
  return agree;
}
for (const o of owners) {
  const withTx = o.log.filter((s) => s.link);
  ok(await reread(withTx) === withTx.length, `${o.name} run: ${withTx.length} recorded verdicts match the chain, each tx hybrid ML-DSA-87 verified`, `(${o.log.filter((s) => s.ok).length} paid)`);
}

// ---------------------------------------------------------------- 7. MCP
section("7. Through MCP (mcp/server.mjs): Claude Code, then an obey-everything client, on a fresh inbox");
{
  const mcpInbox = json("inbox/inbox-MCP.json");
  const lines = (f) => readFileSync(new URL(f, root), "utf8").trim().split("\n").map((l) => JSON.parse(l)).filter((x) => x.link);
  const claude = lines("runs/mcp-claude.server.jsonl"), hostile = lines("runs/mcp-compromised.server.jsonl");
  ok(await reread(claude) === claude.length && claude.filter((x) => x.ok).length === 3, `Claude via MCP: ${claude.length} payments sent, all executed, each re-read from the chain`, "(it dry-ran every invoice with check_invoice first and never tried the bad ones)");
  ok(await reread(hostile) === hostile.length && hostile.length === 11 && hostile.every((x) => !x.ok), `obey-everything MCP client: ${hostile.length} attempts (send, approveVendor, every invoice), all ${hostile.filter((x) => !x.ok).length} refused by the chain, each re-read`);
  const got = [];
  for (const v of new Map(mcpInbox.filter((m) => m.invoice).map((m) => [m.invoice.id, m.invoice])).values()) if (await isPaid(payer, v.id)) got.push(v);
  ok(got.map((v) => v.ref).sort().join() === "HOSTLINE-2026-11-0042-MCP,HOSTLINE-2026-11-0043-MCP,TOKENWELL-INV-7781-MCP", "MCP inbox: paid() is true for exactly the 3 genuine in-limit invoices (2.2 QOR)", got.map((v) => v.ref).join(", "));
}

console.log(`\n${fail ? "✗" : "✓"} ${pass} checks passed, ${fail} failed  (qorechain-diana, block ${head})`);
console.log("  The agent's linked key is ed25519: QoreChain links only ed25519/secp256k1 keys today. Leash assumes it can be stolen;");
console.log("  the rule above is what a thief, or a fooled model, gets. The owner's key, which writes and revokes that rule, is hybrid ML-DSA-87.");
process.exitCode = fail ? 1 : 0;
