// Probe: the agent's own scoped EVM window (the track's "transaction, value, duration and target limits").
// The agent account's human holder (hybrid ML-DSA-87 signature) opens a window on the agent account that
// admits at most N transactions, a total value+fee cap, a block-count expiry, and ONE target: InvoiceDeskV2.
// Inside it, the account's classical secp256k1 key (what an agent would hold) sends ordinary EVM transactions:
//   1. desk.pay(a genuine 5 fUSD invoice)          -> expected: executed (the desk's own checks still apply)
//   2. fUSD.transfer(Mallory, 1)                   -> expected: refused, target not allowed
//   3. 0.01 QOR to Mallory                         -> expected: refused, target not allowed
// Then the window is closed and the same pay-shaped call is tried again -> expected: refused, no window.
// Writes runs/probes/window.json.
import { writeFileSync, readFileSync } from "node:fs";
import { Contract, Interface, JsonRpcProvider, Wallet, parseEther } from "ethers";
import { openEvmWindowMsg, closeEvmWindowMsg, fetchEvmWindow } from "@qorechain/sdk";
import { EVM_CHAIN_ID, EVM_RPC, REST, account, broadcast, readDeployment } from "../lib/chain.mjs";
import { FUSD, signInvoiceV2 } from "../lib/invoices.mjs";

const d = readDeployment().v2, dep = readDeployment();
const aa = await account("agentacct"), o = await account("owner"), b = await account("vendorB");
const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID, { staticNetwork: true });
const agent = new Wallet(aa.privateKey, provider); // the classical half only: all it may do is what a window admits
const desk = new Contract(d.invoiceDesk, JSON.parse(readFileSync(new URL("../build/InvoiceDeskV2.json", import.meta.url), "utf8")).abi, agent);
const out = { what: "the agent account's own scoped EVM window", account: aa.cosmos, accountEvm: aa.evmAddr, steps: [] };
const note = (s) => { out.steps.push(s); console.log(`${s.step.padEnd(44)} ${s.result}${s.tx ? "  " + s.tx : ""}`); };

// 1. open: <= 3 txs, <= 0.4 QOR value+fees, 300 blocks (~7 min), target InvoiceDeskV2 only
const msg = openEvmWindowMsg({ sender: aa.cosmos, blocks: 300, maxTxs: 3, maxValue: "400000" });
msg.value.allowedTargets = [d.invoiceDesk];
const w = await broadcast(aa, [msg], "leash: the agent's scoped EVM window (target: InvoiceDeskV2)");
note({ step: "open window (hybrid ML-DSA-87 signed)", result: w.code ? `REFUSED code ${w.code}: ${w.rawLog}` : "opened", tx: w.transactionHash });
if (w.code) process.exit(1);
await new Promise((r) => setTimeout(r, 4000));
out.window = await fetchEvmWindow({ rest: REST, address: aa.cosmos });
console.log("window as the chain stores it:", JSON.stringify(out.window, (k, v) => (typeof v === "bigint" ? v.toString() : v)));

const send = async (label, fn) => {
  try { const tx = await fn(); const rc = await tx.wait(); note({ step: label, result: rc.status === 1 ? "EXECUTED" : "REVERTED", tx: tx.hash }); }
  catch (e) { const why = e.error?.message ?? e.info?.error?.message ?? e.shortMessage ?? e.message; note({ step: label, result: `REFUSED: ${String(why).replace(/\s+/g, " ").slice(0, 260)}`, tx: e.receipt?.hash }); }
};
// 2. inside the window
const inv = signInvoiceV2(b, { desk: d.invoiceDesk, payer: o.evmAddr, vendor: b.evmAddr, fusd: "5", ref: "TOKENWELL-INV-8803-WINDOW", dueBy: Math.floor(Date.parse("2027-06-30T23:59:59Z") / 1000) });
out.invoice = inv;
await send("desk.pay(genuine 5 fUSD) inside the window", () => desk.pay(o.evmAddr, inv.token, inv.vendor, inv.amount, inv.id, inv.dueBy, inv.signature, { gasLimit: 700_000 }));
const erc = new Contract(FUSD, ["function transfer(address,uint256) returns (bool)"], agent);
await send("fUSD.transfer(Mallory, 1) inside the window", () => erc.transfer(dep.attacker, 1, { gasLimit: 100_000 }));
await send("0.01 QOR to Mallory inside the window", () => agent.sendTransaction({ to: dep.attacker, value: parseEther("0.01"), gasLimit: 30_000 }));
// 3. close, then the same kind of call with no window
const c = await broadcast(aa, [closeEvmWindowMsg(aa.cosmos)], "leash: close the agent's window");
note({ step: "close window", result: c.code ? `code ${c.code}` : "closed", tx: c.transactionHash });
await new Promise((r) => setTimeout(r, 4000));
const inv2 = signInvoiceV2(b, { desk: d.invoiceDesk, payer: o.evmAddr, vendor: b.evmAddr, fusd: "5", ref: "TOKENWELL-INV-8804-WINDOW", dueBy: inv.dueBy });
await send("desk.pay(genuine 5 fUSD) after the window", () => desk.pay(o.evmAddr, inv2.token, inv2.vendor, inv2.amount, inv2.id, inv2.dueBy, inv2.signature, { gasLimit: 700_000 }));
writeFileSync(new URL("../runs/probes/window.json", import.meta.url), JSON.stringify(out, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");
