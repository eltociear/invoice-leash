// Shared chain plumbing: keys, balances, hybrid (secp256k1 + ML-DSA-87) broadcasting.
// QoreChain diana TESTNET only. Never prints key material.
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { StargateClient } from "@cosmjs/stargate";
import { ed25519 } from "@noble/curves/ed25519";
import { EthNativeSigner, deriveUnifiedAccount, generateMnemonic, qorToEvm } from "@qorechain/sdk";

export const CHAIN_ID = "qorechain-diana";
export const EVM_CHAIN_ID = 9800;
export const REST = process.env.QORE_REST ?? "https://api-testnet.qore.host";
export const RPC = process.env.QORE_RPC ?? "https://rpc-testnet.qore.host";
export const EVM_RPC = process.env.QORE_EVM_RPC ?? "https://evm-testnet.qore.host";
export const EXPLORER = "https://explore.qore.network/tx/";
export const DIR = process.env.LEASH_DIR ?? join(homedir(), ".config", "leash");
const KEYS = join(DIR, "keys.env");

// Every role this demo needs. Each is a separate testnet account derived from its own mnemonic.
//   owner     the human. Holds the money, approves vendors, links the agent and writes its rules.
//   gas       the agent's fee wallet. Submits the agent's requests; never holds the owner's money.
//   vendorA   "Hostline": a real vendor with a registered ML-DSA-87 key.
//   vendorB   "Tokenwell": a second real vendor.
//   attacker  "Mallory": has a perfectly valid ML-DSA-87 key of her own, and is not a vendor.
export const ROLES = ["owner", "gas", "vendorA", "vendorB", "attacker"];

export function readKeys() {
  if (!existsSync(KEYS)) throw new Error(`missing ${KEYS}: run "node leash.mjs init" first`);
  return Object.fromEntries(readFileSync(KEYS, "utf8").split("\n").filter((l) => /^[A-Za-z0-9_]+=/.test(l))
    .map((l) => [l.slice(0, l.indexOf("=")), l.slice(l.indexOf("=") + 1).replace(/^"(.*)"$/, "$1")]));
}

export function createKeys() {
  mkdirSync(DIR, { recursive: true, mode: 0o700 });
  if (existsSync(KEYS)) throw new Error(`${KEYS} already exists; not overwriting`);
  const lines = ["# Leash demo keys. QoreChain diana TESTNET only. Never fund on mainnet."];
  for (const r of ROLES) lines.push(`${r}="${generateMnemonic(256)}"`);
  lines.push(`agent=${randomBytes(32).toString("hex")}`);
  writeFileSync(KEYS, lines.join("\n") + "\n", { mode: 0o600 });
  chmodSync(KEYS, 0o600);
  return KEYS;
}

/** Give the owner and the agent fresh keys (keeping the old ones, renamed), for a clean re-run. */
export function rotateOwnerKeys() {
  const tag = Date.now().toString(36);
  const lines = readFileSync(KEYS, "utf8").split("\n").filter(Boolean).map((l) =>
    l.startsWith("owner=") ? l.replace(/^owner=/, `owner_prev_${tag}=`) : l.startsWith("agent=") ? l.replace(/^agent=/, `agent_prev_${tag}=`) : l);
  lines.push(`owner="${generateMnemonic(256)}"`, `agent=${randomBytes(32).toString("hex")}`);
  writeFileSync(KEYS, lines.join("\n") + "\n", { mode: 0o600 });
  delete cache.owner;
  return `owner_prev_${tag}`;
}

export async function accountFromKey(name) {
  const acc = await deriveUnifiedAccount(readKeys()[name], 0);
  acc.role = name; acc.evmAddr = qorToEvm(acc.cosmos);
  return acc;
}

const cache = {};
export async function account(role) {
  if (!cache[role]) {
    const acc = await deriveUnifiedAccount(readKeys()[role], 0);
    acc.role = role;
    acc.evmAddr = qorToEvm(acc.cosmos);
    cache[role] = acc;
  }
  return cache[role];
}

/** The agent's ed25519 key. It holds no money; it can only ask to act for the owner, inside the rules. */
export function agentKey() {
  const sk = Uint8Array.from(Buffer.from(readKeys().agent, "hex"));
  const pk = ed25519.getPublicKey(sk);
  return { sk, pk, wallet: { publicKey: pk, async signMessage(m) { return { signature: ed25519.sign(m, sk) }; } } };
}

export async function getJson(path) {
  const r = await fetch(`${REST}${path}`);
  return r.status === 200 ? r.json() : null;
}

export async function balance(addr) {
  const b = await getJson(`/cosmos/bank/v1beta1/balances/${addr}`);
  return b?.balances?.find((x) => x.denom === "uqor")?.amount ?? "0";
}

export const toUqor = (qor) => {
  if (!/^\d+(\.\d{1,6})?$/.test(String(qor))) throw new Error(`amount in QOR, e.g. 1 or 0.5 (got "${qor}")`);
  const [i, f = ""] = String(qor).split(".");
  return BigInt(i) * 1000000n + BigInt((f + "000000").slice(0, 6));
};
export const uqorToWei = (u) => BigInt(u) * 10n ** 12n;
export const fmt = (uqor) => `${(Number(uqor) / 1e6).toLocaleString("en-US", { maximumFractionDigits: 6 })} QOR`;
export const hex = (b) => Buffer.from(b).toString("hex");

/** Sign with the account's keys and broadcast. mode "hybrid" (normal) or "classical" (only the one-time PQC registration). */
export async function broadcast(acc, messages, memo = "", mode = "hybrid", gasLimit) {
  const a = await getJson(`/cosmos/auth/v1beta1/accounts/${acc.cosmos}`);
  const base = a?.account?.base_account ?? a?.account ?? {};
  const signer = new EthNativeSigner(acc, { signMode: mode, rest: REST });
  const transport = await StargateClient.connect(RPC);
  const req = { chainId: CHAIN_ID, accountNumber: BigInt(base.account_number ?? 0), sequence: BigInt(base.sequence ?? 0), memo, messages };
  try {
    let gas = gasLimit ?? 800000;
    if (!gasLimit) {
      try { const sim = await signer.simulate?.(transport, req); if (sim) gas = Math.ceil(Number(sim) * 1.4); } catch { /* keep the default */ }
    }
    const fee = { amount: [{ denom: "uqor", amount: String(Math.ceil(gas * 0.15)) }], gas: String(gas) };
    return await signer.signAndBroadcast(transport, { ...req, fee });
  } finally { transport.disconnect(); }
}

/** The chain's own record of a transaction: its events and whether the hybrid ML-DSA-87 check passed. */
export async function onChain(hash) {
  for (let i = 0; i < 20; i++) {
    const t = await getJson(`/cosmos/tx/v1beta1/txs/${hash}`);
    if (t) {
      const ev = t.tx_response.events.filter((e) => e.type === "pqc_hybrid_verify")
        .map((e) => Object.fromEntries(e.attributes.map((x) => [x.key, x.value])));
      return { code: t.tx_response.code, events: t.tx_response.events, hybrid: ev.some((e) => e.status === "verified") };
    }
    await new Promise((s) => setTimeout(s, 3000));
  }
  return null;
}

export const bankSend = (from, to, uqor) => ({
  typeUrl: "/cosmos.bank.v1beta1.MsgSend",
  value: { fromAddress: from, toAddress: to, amount: [{ denom: "uqor", amount: String(uqor) }] },
});

/** Public, non-secret deployment facts (addresses, the desk contract) kept next to the code. */
const DEPLOY = new URL("../deployment.json", import.meta.url);
export const readDeployment = () => (existsSync(DEPLOY) ? JSON.parse(readFileSync(DEPLOY, "utf8")) : {});
export const writeDeployment = (d) => writeFileSync(DEPLOY, JSON.stringify(d, null, 2) + "\n");
