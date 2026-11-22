// Probes for the v2 leash (fUSD only): can the agent key move value outside InvoiceDeskV2.pay?
//   node scripts/probe-v2.mjs value   a plain EVM value transfer of 0.01 QOR to a fresh address
//   node scripts/probe-v2.mjs token   fUSD.transfer(fresh address, 1 fUSD), straight to the token
import { buildPhantomExecuteEvm, fetchAuthNonce, resolveEvmAuthDigestVersion, decodeAuthenticatorExecutions } from "@qorechain/sdk";
import { Wallet, Interface } from "ethers";
import { CHAIN_ID, REST, EXPLORER, account, agentKey, broadcast, onChain } from "../lib/chain.mjs";
import { FUSD } from "../lib/invoices.mjs";
const mode = process.argv[2];
const owner = await account("owner"), gas = await account("gas"), k = agentKey();
const to = Wallet.createRandom().address;
const { nonce } = await fetchAuthNonce({ rest: REST, address: owner.cosmos, pubkey: k.pk });
const digestVersion = await resolveEvmAuthDigestVersion({ rest: REST });
const p = mode === "token"
  ? { to: FUSD, value: "0", data: new Interface(["function transfer(address,uint256)"]).encodeFunctionData("transfer", [to, 1_000_000n]) }
  : { to, value: (10n ** 16n).toString(), data: "0x" };
const msg = await buildPhantomExecuteEvm({ wallet: k.wallet, relayer: gas.cosmos, chainId: CHAIN_ID, account: owner.cosmos, ...p,
  data: Uint8Array.from(Buffer.from(p.data.slice(2), "hex")), gasLimit: 200_000, nonce, digestVersion });
let out;
try {
  const res = await broadcast(gas, [msg], `probe v2: ${mode}`, "hybrid", 500_000);
  const c = await onChain(res.transactionHash);
  const [x] = decodeAuthenticatorExecutions({ msgResponses: res.msgResponses ?? [], events: c?.events ?? [] }, [msg]);
  out = { mode, to, executed: !!x?.success, reason: x?.reason ?? null, tx: res.transactionHash };
} catch (e) {
  const t = String(e?.message ?? e).replace(/\s+/g, " ");
  out = { mode, to, executed: false, reason: t.slice(0, 300), tx: t.match(/\(tx ([0-9A-F]{64})/)?.[1] ?? null };
}
console.log(JSON.stringify(out));
