// Our own Q-Day drill. Assume a quantum computer has broken every elliptic-curve key in the system:
// the secp256k1 half of every account (company, agent account, relayer, vendors). The attacker signs
// with those classical keys only (no ML-DSA-87), the way Shor's algorithm would let them, and tries
// everything that would hurt Invoice Leash. Each attempt is sent to the live testnet.
//
//   node scripts/qday-drill.mjs        writes runs/qday-drill.json; npm run verify re-checks the state
//
// The ed25519 agent key is classical too; what it can do is already the compromised-agent run (16
// attempts, 3 genuine invoices paid). It is not repeated here.
import { writeFileSync } from "node:fs";
import { Interface, JsonRpcProvider, Wallet, parseEther, randomBytes } from "ethers";
import { closeEvmWindowMsg, linkAuthenticatorMsgs, openEvmWindowMsg, signAuthenticatorLinkEd25519 } from "@qorechain/sdk";
import { CHAIN_ID, EVM_CHAIN_ID, EVM_RPC, account, bankSend, broadcast, readDeployment, toUqor } from "../lib/chain.mjs";
import { FUSD } from "../lib/invoices.mjs";
import { registerKemMsg } from "../lib/sealed.mjs";
import { sealKeysFromSeed } from "@qorechain/qoreseal";

const dep = readDeployment(), d = dep.v2, MALLORY = dep.attacker;
const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID, { staticNetwork: true });
const desk = new Interface(["function approveVendor(address)", "function setLimit(address,uint256,uint256)", "function setAgent(address,bool)"]);
const erc20 = new Interface(["function transfer(address,uint256) returns (bool)", "function approve(address,uint256) returns (bool)"]);
const out = { what: "Q-Day drill: every account's classical (secp256k1) key, used alone", at: new Date().toISOString(), attempts: [] };
const NET = /fetch failed|ETIMEDOUT|ECONNRESET|ENETUNREACH|EAI_AGAIN|socket hang up|timeout|could not coalesce/i;
const clean = (e) => String(e?.message ?? e).replace(/\s+/g, " ").slice(0, 300);

async function cosmos(role, label, msgs) {
  const acc = await account(role);
  let r, refused, why, tx;
  for (let i = 0; ; i++) {
    try { r = await broadcast(acc, msgs, "leash: Q-Day drill (classical key only)", "classical"); tx = r.transactionHash; refused = r.code !== 0; why = refused ? `code ${r.code}: ${r.rawLog}` : "EXECUTED"; break; }
    catch (e) {
      why = clean(e);
      if (NET.test(why) && i < 5) { await new Promise((res) => setTimeout(res, 5000)); continue; } // our network, not the chain's answer
      if (NET.test(why)) throw new Error(`network kept failing: ${why}`);
      refused = true; tx = why.match(/[0-9A-F]{64}/)?.[0]; break;
    }
  }
  out.attempts.push({ role, address: acc.cosmos, lane: "cosmos, classical signature only", label, refused, why: why.slice(0, 300), tx });
  console.log(`${refused ? "REFUSED " : "EXECUTED"} ${role.padEnd(9)} ${label}\n          ${why.slice(0, 160)}`);
}
async function evm(role, label, tx) {
  const acc = await account(role), w = new Wallet(acc.privateKey, provider);
  let refused, why, hash;
  for (let i = 0; ; i++) {
    try { const t = await w.sendTransaction({ gasLimit: 300_000, ...tx }); hash = t.hash; const rc = await t.wait(); refused = rc.status !== 1; why = refused ? "reverted" : "EXECUTED"; break; }
    catch (e) {
      why = clean(e.error?.message ?? e.info?.error?.message ?? e.shortMessage ?? e);
      if (NET.test(why) && i < 5) { await new Promise((res) => setTimeout(res, 5000)); continue; }
      if (NET.test(why)) throw new Error(`network kept failing: ${why}`);
      refused = true; break;
    }
  }
  out.attempts.push({ role, address: acc.cosmos, lane: "EVM, secp256k1 signature", label, refused, why, tx: hash });
  console.log(`${refused ? "REFUSED " : "EXECUTED"} ${role.padEnd(9)} ${label}\n          ${why.slice(0, 160)}`);
}

const company = await account("owner"), aa = await account("agentacct");
// 1. take the company's money
await cosmos("owner", "send 1 QOR to the attacker (MsgSend)", [bankSend(company.cosmos, MALLORY_COSMOS(), toUqor("1"))]);
await evm("owner", "send 1 QOR to the attacker (EVM)", { to: MALLORY, value: parseEther("1") });
await evm("owner", "fUSD.transfer(attacker, 100)", { to: FUSD, data: erc20.encodeFunctionData("transfer", [MALLORY, 100_000_000n]) });
await evm("owner", "fUSD.approve(attacker, max): pull it later", { to: FUSD, data: erc20.encodeFunctionData("approve", [MALLORY, 2n ** 255n]) });
// 2. loosen the leash
await evm("owner", "desk.approveVendor(attacker)", { to: d.invoiceDesk, data: desk.encodeFunctionData("approveVendor", [MALLORY]) });
await evm("owner", "desk.setLimit(fUSD, 10^12, 10^12)", { to: d.invoiceDesk, data: desk.encodeFunctionData("setLimit", [FUSD, 10n ** 12n, 10n ** 12n]) });
await evm("owner", "desk.setAgent(attacker, true)", { to: d.invoiceDesk, data: desk.encodeFunctionData("setAgent", [MALLORY, true]) });
// 3. get around the window rule: open a window with the classical key
await cosmos("owner", "open an EVM window (MsgOpenEVMWindow), to then use the classical key", [openEvmWindowMsg({ sender: company.cosmos, blocks: 300, maxTxs: 5, maxValue: String(toUqor("5")) })]);
await cosmos("agentacct", "open an EVM window on the agent account", [openEvmWindowMsg({ sender: aa.cosmos, blocks: 300, maxTxs: 5, maxValue: String(toUqor("0.5")) })]);
// 4. take over the agent account: link the attacker's own key, or swap the KEM key to read sealed invoices
const ask = randomBytes(32), proof = signAuthenticatorLinkEd25519({ chainId: CHAIN_ID, account: aa.cosmos, privateKey: ask });
await cosmos("agentacct", "link the attacker's ed25519 key to the agent account, no limits", linkAuthenticatorMsgs({ owner: aa.cosmos, chainId: CHAIN_ID, ...proof, permissions: ["evm", "send"], expiryUnix: Math.floor(Date.now() / 1000) + 86400, label: "attacker", spendingRule: { id: "attacker", enabled: true, perTxLimit: "1000000000000", dailyLimit: "1000000000000", allowedDenoms: ["uqor"], allowedEvmCalls: [] } }));
await cosmos("agentacct", "replace the agent's ML-KEM-1024 key with the attacker's (read future sealed invoices)", [registerKemMsg(aa.cosmos, sealKeysFromSeed(randomBytes(32)))]);
await evm("agentacct", "send the agent account's QOR to the attacker (EVM)", { to: MALLORY, value: parseEther("0.1") });
// 5. the relayer and a vendor
await cosmos("gas", "send the relayer's QOR to the attacker", [bankSend((await account("gas")).cosmos, MALLORY_COSMOS(), toUqor("1"))]);
await evm("vendorA", "Hostline's fUSD to the attacker", { to: FUSD, data: erc20.encodeFunctionData("transfer", [MALLORY, 1n]) });
// control: the same kind of request, signed hybrid (ML-DSA-87 + secp256k1) by the real company, goes through
const c = await broadcast(company, [bankSend(company.cosmos, company.cosmos, "1")], "leash: Q-Day drill control (hybrid)");
out.control = { label: "the company sends 1 uqor to itself, hybrid-signed", code: c.code, tx: c.transactionHash };
console.log(`control  hybrid-signed MsgSend: code ${c.code}  ${c.transactionHash}`);
writeFileSync(new URL("../runs/qday-drill.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
console.log(`\n${out.attempts.filter((a) => a.refused).length} of ${out.attempts.length} refused`);

function MALLORY_COSMOS() { return "qor1xle4mhhmsksk5rqn5ft8mat62pr553sfu97l9t"; }
