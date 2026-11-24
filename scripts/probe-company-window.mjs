// Probe: the company's own EVM window, with a quantum attacker who holds the company's classical key.
// The company opens a window the way `approve-v2` and the kill switch do: one target (InvoiceDeskV2),
// one transaction. While it is open, the attacker signs with the company's secp256k1 key alone:
//   1. fUSD.transfer(Mallory, 1)            -> expected: refused, fUSD is not the window's target
//   2. 1 QOR to Mallory                     -> expected: refused, Mallory is not the window's target
//   3. the treasury: a MsgSend of the bank-coin fUSD (Cosmos lane, classical signature only)
//                                           -> expected: refused, code 20 (it needs ML-DSA-87)
// Then the company uses its one slot (a harmless call to the desk) and closes the window.
// Writes runs/probes/company-window.json.
import { writeFileSync } from "node:fs";
import { Interface, JsonRpcProvider, Wallet, parseEther } from "ethers";
import { openEvmWindowMsg, closeEvmWindowMsg } from "@qorechain/sdk";
import { EVM_CHAIN_ID, EVM_RPC, REST, account, broadcast, readDeployment } from "../lib/chain.mjs";
import { FUSD } from "../lib/invoices.mjs";

const dep = readDeployment(), d = dep.v2, MALLORY = dep.attacker, MALLORY_COSMOS = "qor1xle4mhhmsksk5rqn5ft8mat62pr553sfu97l9t";
const o = await account("owner");
const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID, { staticNetwork: true });
const key = new Wallet(o.privateKey, provider); // the classical half: what Shor's algorithm would give the attacker
const erc20 = new Interface(["function transfer(address,uint256) returns (bool)"]);
const desk = new Interface(["function paid(address,bytes32) view returns (bool)"]);
const out = { what: "the company's own scoped window, against an attacker holding the company's classical key", company: o.cosmos, steps: [] };
const note = (s) => { out.steps.push(s); console.log(`${s.step.padEnd(58)} ${s.result.slice(0, 200)}${s.tx ? "  " + s.tx : ""}`); };
const clean = (e) => String(e.error?.message ?? e.info?.error?.message ?? e.shortMessage ?? e.message ?? e).replace(/\s+/g, " ").slice(0, 300);
const evm = async (label, tx) => {
  try { const t = await key.sendTransaction({ gasLimit: 100_000, ...tx }); const rc = await t.wait(); note({ step: label, result: rc.status === 1 ? "EXECUTED" : "REVERTED", tx: t.hash }); }
  catch (e) { note({ step: label, result: `REFUSED: ${clean(e)}` }); }
};

const msg = openEvmWindowMsg({ sender: o.cosmos, blocks: 300, maxTxs: 1, maxValue: "500000" });
msg.value.allowedTargets = [d.invoiceDesk];
const w = await broadcast(o, [msg], "leash: company window, scoped to the desk");
note({ step: "company opens a window: InvoiceDeskV2 only, 1 tx (hybrid)", result: w.code ? `REFUSED code ${w.code}: ${w.rawLog}` : "opened", tx: w.transactionHash });
if (w.code) process.exit(1);
await new Promise((r) => setTimeout(r, 4000));

await evm("attacker, classical key: fUSD.transfer(Mallory, 1)", { to: FUSD, data: erc20.encodeFunctionData("transfer", [MALLORY, 1n]) });
await evm("attacker, classical key: 1 QOR to Mallory", { to: MALLORY, value: parseEther("1"), gasLimit: 21_000 });
const coin = (await (await fetch(`${REST}/cosmos/bank/v1beta1/balances/${o.cosmos}`)).json()).balances.find((x) => x.denom.toLowerCase() === `erc20:${FUSD}`.toLowerCase());
out.treasury = coin.amount;
try {
  const r = await broadcast(o, [{ typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: { fromAddress: o.cosmos, toAddress: MALLORY_COSMOS, amount: [{ denom: coin.denom, amount: coin.amount }] } }], "Q-Day: take the treasury", "classical");
  note({ step: "attacker, classical key: MsgSend the whole treasury (bank fUSD)", result: r.code ? `REFUSED code ${r.code}: ${r.rawLog}` : "EXECUTED", tx: r.transactionHash });
} catch (e) { note({ step: "attacker, classical key: MsgSend the whole treasury (bank fUSD)", result: `REFUSED: ${clean(e)}` }); }

await evm("company uses its one slot (a call to the desk)", { to: d.invoiceDesk, data: desk.encodeFunctionData("paid", [o.evmAddr, "0x" + "00".repeat(32)]), gasLimit: 60_000 });
const c = await broadcast(o, [closeEvmWindowMsg(o.cosmos)], "leash: close the company window").catch((e) => ({ code: -1, rawLog: e.message }));
note({ step: "close window", result: c.code ? `not needed or refused: ${String(c.rawLog).slice(0, 160)}` : "closed", tx: c.transactionHash });
writeFileSync(new URL("../runs/probes/company-window.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
