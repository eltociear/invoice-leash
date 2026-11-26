// Probe: the live agent account's own scoped EVM window, on InvoiceDeskV4 (the track's "transaction, value,
// duration and target limits"). The agent account's holder (hybrid ML-DSA-87 signature) opens a window that
// admits at most 3 transactions, a value+fee cap, 300 blocks, and ONE target: the live InvoiceDeskV4.
// Inside it, the account's classical secp256k1 key sends ordinary EVM transactions:
//   1. desk.pay(a genuine unpaid 1 fUSD invoice) with NO agent ML-DSA-87 signature
//        -> expected: reverted on chain, BadAgentSignature: inside an open window, the classical key alone
//           (what a quantum computer could derive) still pays nothing
//   2. the same invoice, with the agent signer's ML-DSA-87 signature  -> expected: executed
//   3. fUSD.transfer(Mallory, 1)   -> expected: refused by the window (target not allowed)
//   4. 0.01 QOR to Mallory          -> expected: refused by the window (target not allowed)
// Then the window is closed, and a pay-shaped call is refused: no window.
//   LEASH_DIR=<keys: agentacct, agentsigner, vendor> LEASH_DEPLOYMENT=runs/live/desk-v4.json node scripts/probe-window-v4.mjs
// Writes runs/probes/window-v4.json.
import { writeFileSync, readFileSync } from "node:fs";
import { Contract, Interface, JsonRpcProvider, Wallet, parseEther } from "ethers";
import { openEvmWindowMsg, closeEvmWindowMsg, fetchEvmWindow } from "@qorechain/sdk";

const ROOT = new URL("../", import.meta.url);
process.env.LEASH_DEPLOYMENT ??= new URL("runs/live/desk-v4.json", ROOT).pathname;
const { EVM_CHAIN_ID, EVM_RPC, REST, account, broadcast, readDeployment } = await import("../lib/chain.mjs");
const { FUSD, signInvoiceV2, signAgentPayV4 } = await import("../lib/invoices.mjs");
const { isPaid } = await import("../lib/agent.mjs");

const d = readDeployment().v2, MALLORY = "0x37F35dDeFb85A16A0c13A2567DF57a50474a4609";
if (d.version !== 4) throw new Error("not an InvoiceDeskV4");
const aa = await account("agentacct"), signer = await account("agentsigner"), vendor = await account("vendor");
if (aa.evmAddr.toLowerCase() !== d.agentAccountEvm.toLowerCase()) throw new Error("agentacct is not this desk's agent account");
const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID, { staticNetwork: true });
const agent = new Wallet(aa.privateKey, provider); // the classical half only
const abi = JSON.parse(readFileSync(new URL("build/InvoiceDeskV4.json", ROOT), "utf8")).abi, iface = new Interface(abi);
const desk = new Contract(d.invoiceDesk, abi, agent);
const out = { what: "the live agent account's own scoped EVM window, on InvoiceDeskV4", desk: d.invoiceDesk, account: aa.cosmos, accountEvm: aa.evmAddr, steps: [] };
const note = (s) => { out.steps.push(s); console.log(`${s.step.padEnd(62)} ${s.result}${s.tx ? "  " + s.tx : ""}`); };
const save = () => writeFileSync(new URL("runs/probes/window-v4.json", ROOT), JSON.stringify(out, (k, v) => (typeof v === "bigint" ? v.toString() : v), 2) + "\n");

const series = Date.now().toString(36).toUpperCase(), dueBy = Math.floor(Date.now() / 1000) + 30 * 86400;
const inv = signInvoiceV2(vendor, { desk: d.invoiceDesk, payer: d.payerEvm, vendor: vendor.evmAddr, token: FUSD, fusd: "1", ref: `DH-WINDOW-${series}`, dueBy });
const inv2 = signInvoiceV2(vendor, { desk: d.invoiceDesk, payer: d.payerEvm, vendor: vendor.evmAddr, token: FUSD, fusd: "1", ref: `DH-WINDOW-AFTER-${series}`, dueBy });
const agentSig = (i) => signAgentPayV4(signer, { desk: d.invoiceDesk, payer: d.payerEvm, agent: aa.evmAddr, vendor: i.vendor, token: i.token, amount: BigInt(i.amount), id: i.id });
const args = (i) => [d.payerEvm, i.token, i.vendor, i.amount, i.id, i.dueBy, i.signature];
out.invoice = inv;

// 1. open: <= 3 txs, <= 0.9 QOR value+fees, 300 blocks, target: the live InvoiceDeskV4 only
const msg = openEvmWindowMsg({ sender: aa.cosmos, blocks: 300, maxTxs: 3, maxValue: "900000" });
msg.value.allowedTargets = [d.invoiceDesk];
const w = await broadcast(aa, [msg], "leash: the agent's scoped EVM window (target: InvoiceDeskV4)");
note({ step: "open window (hybrid ML-DSA-87 signed)", result: w.code ? `REFUSED code ${w.code}: ${w.rawLog}` : "opened", tx: w.transactionHash });
if (w.code) { save(); process.exit(1); }
await new Promise((r) => setTimeout(r, 4000));
out.window = await fetchEvmWindow({ rest: REST, address: aa.cosmos });

const send = async (label, fn, simulate) => {
  let reason;
  if (simulate) { try { await provider.call({ ...simulate, from: aa.evmAddr }); reason = "would succeed"; } catch (e) { try { reason = iface.parseError(e.data ?? e.info?.error?.data)?.name; } catch { reason = e.shortMessage; } } }
  try { const tx = await fn(); const rc = await tx.wait(); note({ step: label, result: rc.status === 1 ? "EXECUTED" : `REVERTED${reason ? ": " + reason : ""}`, tx: tx.hash }); }
  catch (e) {
    if (e.receipt) note({ step: label, result: `REVERTED${reason ? ": " + reason : ""}`, tx: e.receipt.hash });
    else note({ step: label, result: `REFUSED: ${String(e.error?.message ?? e.info?.error?.message ?? e.shortMessage ?? e.message).replace(/\s+/g, " ").slice(0, 260)}` });
  }
};
// 2. inside the window
out.unpaidBefore = !(await isPaid(d, inv));
await send("desk.pay(genuine unpaid 1 fUSD) with the classical key alone", () => desk.pay(...args(inv), "0x", { gasLimit: 1_000_000 }),
  { to: d.invoiceDesk, data: iface.encodeFunctionData("pay", [...args(inv), "0x"]) });
await send("the same invoice, with the agent signer's ML-DSA-87 signature", () => desk.pay(...args(inv), agentSig(inv), { gasLimit: 1_000_000 }));
const erc = new Contract(FUSD, ["function transfer(address,uint256) returns (bool)"], agent);
await send("fUSD.transfer(Mallory, 1) inside the window", () => erc.transfer(MALLORY, 1, { gasLimit: 100_000 }));
await send("0.01 QOR to Mallory inside the window", () => agent.sendTransaction({ to: MALLORY, value: parseEther("0.01"), gasLimit: 30_000 }));
// 3. close, then a pay-shaped call with no window
const c = await broadcast(aa, [closeEvmWindowMsg(aa.cosmos)], "leash: close the agent's window");
note({ step: "close window", result: c.code ? `code ${c.code}` : "closed", tx: c.transactionHash });
await new Promise((r) => setTimeout(r, 4000));
await send("desk.pay(genuine 1 fUSD, signed) after the window", () => desk.pay(...args(inv2), agentSig(inv2), { gasLimit: 1_000_000 }));
out.at = new Date().toISOString();
save();
