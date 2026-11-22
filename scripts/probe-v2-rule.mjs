// Probe a v2 rule where fUSD is NOT in allowed_denoms: only a placeholder ERC-20 denom is listed (so
// no QOR may move), and the agent may call InvoiceDeskV2.pay only.
//   node scripts/probe-v2-rule.mjs set      replace the owner's rule (MsgUpdateSpendingRules only)
//   node scripts/probe-v2-rule.mjs pay      pay a fresh 1 fUSD genuine invoice through the desk
import { linkAuthenticatorMsgs, signAuthenticatorLinkEd25519, buildPhantomExecuteEvm, fetchAuthNonce, resolveEvmAuthDigestVersion, decodeAuthenticatorExecutions } from "@qorechain/sdk";
import { Interface } from "ethers";
import { readFileSync } from "node:fs";
import { CHAIN_ID, REST, EXPLORER, account, agentKey, broadcast, onChain, readDeployment } from "../lib/chain.mjs";
import { signInvoiceV2 } from "../lib/invoices.mjs";
const d = readDeployment().v2, o = await account("owner"), k = agentKey(), gas = await account("gas");
const ABI = JSON.parse(readFileSync(new URL("../build/InvoiceDeskV2.json", import.meta.url), "utf8")).abi, desk = new Interface(ABI);
const PLACEHOLDER = "erc20/0x000000000000000000000000000000000000dead";
if (process.argv[2] === "set") {
  const proof = signAuthenticatorLinkEd25519({ chainId: CHAIN_ID, account: o.cosmos, privateKey: k.sk });
  const [update] = linkAuthenticatorMsgs({ owner: o.cosmos, chainId: CHAIN_ID, ...proof, permissions: ["evm"], expiryUnix: Math.floor(Date.now() / 1000) + 72 * 3600, label: "probe",
    spendingRule: { id: "leash-v2", enabled: true, perTxLimit: "0", dailyLimit: "0", allowedDenoms: [PLACEHOLDER], denomLimits: [{ denom: PLACEHOLDER, perTxLimit: "1", dailyLimit: "1" }],
      allowedEvmCalls: [`${d.invoiceDesk.toLowerCase()}/${desk.getFunction("pay").selector}`] } });
  const res = await broadcast(o, [update], "probe: rule without fUSD in allowed_denoms");
  console.log(JSON.stringify({ set: res.code === 0, tx: res.transactionHash, log: res.rawLog?.slice(0, 200) }));
} else {
  const vA = await account("vendorA");
  const inv = signInvoiceV2(vA, { desk: d.invoiceDesk, payer: o.evmAddr, vendor: vA.evmAddr, fusd: "1", ref: `PROBE-${Date.now()}`, dueBy: Math.floor(Date.now() / 1000) + 86400 });
  const { nonce } = await fetchAuthNonce({ rest: REST, address: o.cosmos, pubkey: k.pk });
  const msg = await buildPhantomExecuteEvm({ wallet: k.wallet, relayer: gas.cosmos, chainId: CHAIN_ID, account: o.cosmos, to: d.invoiceDesk, value: "0",
    data: Uint8Array.from(Buffer.from(desk.encodeFunctionData("pay", [inv.token, inv.vendor, inv.amount, inv.id, inv.dueBy, inv.signature]).slice(2), "hex")),
    gasLimit: 650_000, nonce, digestVersion: await resolveEvmAuthDigestVersion({ rest: REST }) });
  try {
    const res = await broadcast(gas, [msg], "probe v2: pay 1 fUSD", "hybrid", 1_000_000);
    const c = await onChain(res.transactionHash);
    const [x] = decodeAuthenticatorExecutions({ msgResponses: res.msgResponses ?? [], events: c?.events ?? [] }, [msg]);
    console.log(JSON.stringify({ pay: x?.success ? "EXECUTED" : "failed", reason: x?.reason ?? null, ref: inv.ref, tx: res.transactionHash }));
  } catch (e) { const t = String(e?.message ?? e).replace(/\s+/g, " "); console.log(JSON.stringify({ pay: "refused", reason: t.slice(0, 300), tx: t.match(/\(tx ([0-9A-F]{64})/)?.[1] ?? null })); }
}
