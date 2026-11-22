// Probe: can the agent's key make a plain EVM value transfer (no call data) to an arbitrary address?
import { buildPhantomExecuteEvm, fetchAuthNonce, resolveEvmAuthDigestVersion, decodeAuthenticatorExecutions } from "@qorechain/sdk";
import { Wallet } from "ethers";
import { CHAIN_ID, REST, EXPLORER, account, agentKey, broadcast, onChain } from "../lib/chain.mjs";
const owner = await account("owner"), gas = await account("gas"), k = agentKey();
const to = Wallet.createRandom().address;
const { nonce } = await fetchAuthNonce({ rest: REST, address: owner.cosmos, pubkey: k.pk });
const digestVersion = await resolveEvmAuthDigestVersion({ rest: REST });
const msg = await buildPhantomExecuteEvm({ wallet: k.wallet, relayer: gas.cosmos, chainId: CHAIN_ID, account: owner.cosmos, to, value: (10n ** 16n).toString(), data: new Uint8Array(), gasLimit: 100_000, nonce, digestVersion });
try {
  const res = await broadcast(gas, [msg], "probe: plain value transfer", "hybrid", 400_000);
  const c = await onChain(res.transactionHash);
  const [x] = decodeAuthenticatorExecutions({ msgResponses: res.msgResponses ?? [], events: c?.events ?? [] }, [msg]);
  console.log("to", to, "code", res.code, "exec", x?.success ? "SUCCEEDED" : `failed: ${x?.reason}`, EXPLORER + res.transactionHash);
} catch (e) { console.log("refused:", String(e.message).slice(0, 400)); }
