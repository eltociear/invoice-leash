// Probe: an open EVM window is the one place a classical (secp256k1) key acts alone, so after Q-Day it is
// what a quantum attacker could use. This checks that the window's own caps hold, not only its target list.
// The agent account opens a window (hybrid ML-DSA-87 signed) that admits ONE transaction, to InvoiceDeskV2.
// Its classical key then sends two harmless calls to the desk (a read, sent as a transaction: no money moves):
//   1. the first                      -> expected: executed
//   2. the second, same target        -> expected: refused, the window's transaction count is used up
// Then a second window that admits 2 transactions but only 0.02 QOR of value plus fees:
//   3. a call carrying 0.05 QOR       -> expected: refused, over the window's value cap
// Writes runs/probes/window-caps.json.
import { writeFileSync } from "node:fs";
import { Interface, JsonRpcProvider, Wallet } from "ethers";
import { openEvmWindowMsg, closeEvmWindowMsg, fetchEvmWindow } from "@qorechain/sdk";
import { EVM_CHAIN_ID, EVM_RPC, REST, account, broadcast, readDeployment } from "../lib/chain.mjs";

const d = readDeployment().v2;
const aa = await account("agentacct"), o = await account("owner");
const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID, { staticNetwork: true });
const key = new Wallet(aa.privateKey, provider);
const desk = new Interface(["function paid(address,bytes32) view returns (bool)"]);
const data = desk.encodeFunctionData("paid", [o.evmAddr, "0x" + "00".repeat(32)]);
const out = { what: "the EVM window's transaction cap, against the account's classical key", account: aa.cosmos, steps: [] };
const big = (k, v) => (typeof v === "bigint" ? v.toString() : v);
const note = (s) => { out.steps.push(s); console.log(`${s.step.padEnd(52)} ${s.result}${s.tx ? "  " + s.tx : ""}`); };

const msg = openEvmWindowMsg({ sender: aa.cosmos, blocks: 100, maxTxs: 1, maxValue: "100000" });
msg.value.allowedTargets = [d.invoiceDesk];
const w = await broadcast(aa, [msg], "leash: window with a one-transaction cap");
note({ step: "open window: 1 tx, 0.1 QOR, 100 blocks, InvoiceDeskV2 (hybrid)", result: w.code ? `REFUSED code ${w.code}: ${w.rawLog}` : "opened", tx: w.transactionHash });
if (w.code) process.exit(1);
await new Promise((r) => setTimeout(r, 4000));
out.windowAtOpen = await fetchEvmWindow({ rest: REST, address: aa.cosmos });

const send = async (label, value = 0n) => {
  try { const t = await key.sendTransaction({ to: d.invoiceDesk, data, value, gasLimit: 60_000 }); const rc = await t.wait(); note({ step: label, result: rc.status === 1 ? "EXECUTED" : "REVERTED", tx: t.hash }); }
  catch (e) { const why = e.error?.message ?? e.info?.error?.message ?? e.shortMessage ?? e.message; note({ step: label, result: `REFUSED: ${String(why).replace(/\s+/g, " ").slice(0, 300)}` }); }
  await new Promise((r) => setTimeout(r, 3000));
};
await send("1st classical tx to the desk (a read, no value)");
out.windowAfterFirst = await fetchEvmWindow({ rest: REST, address: aa.cosmos });
await send("2nd classical tx, same target, same kind");

const c = await broadcast(aa, [closeEvmWindowMsg(aa.cosmos)], "leash: close the capped window").catch((e) => ({ code: -1, rawLog: e.message }));
note({ step: "close window", result: c.code ? `not needed or refused: ${String(c.rawLog).slice(0, 160)}` : "closed", tx: c.transactionHash });
const msg2 = openEvmWindowMsg({ sender: aa.cosmos, blocks: 100, maxTxs: 2, maxValue: "20000" });
msg2.value.allowedTargets = [d.invoiceDesk];
const w2 = await broadcast(aa, [msg2], "leash: window with a 0.02 QOR cap");
note({ step: "open window: 2 txs, 0.02 QOR, 100 blocks, InvoiceDeskV2 (hybrid)", result: w2.code ? `REFUSED code ${w2.code}: ${w2.rawLog}` : "opened", tx: w2.transactionHash });
if (w2.code) process.exit(1);
await new Promise((r) => setTimeout(r, 4000));
await send("classical tx carrying 0.05 QOR (cap 0.02)", 50_000_000_000_000_000n);
const c2 = await broadcast(aa, [closeEvmWindowMsg(aa.cosmos)], "leash: close the value-capped window").catch((e) => ({ code: -1, rawLog: e.message }));
note({ step: "close window", result: c2.code ? `not needed or refused: ${String(c2.rawLog).slice(0, 160)}` : "closed", tx: c2.transactionHash });
writeFileSync(new URL("../runs/probes/window-caps.json", import.meta.url), JSON.stringify(out, big, 2) + "\n");
