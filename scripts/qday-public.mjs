// "Shor's gift": an account whose classical key is PUBLIC, as if a quantum computer had already broken it.
// The account holds 5 QOR and has a registered ML-DSA-87 key, which stays secret. Its secp256k1 private
// key is published in runs/qday-public.json, the README and the attack lab: anyone can sign anything with
// it. The chain still refuses every transaction that lacks the ML-DSA-87 signature, so the 5 QOR stay.
//
//   node scripts/qday-public.mjs setup     fund 5 QOR (company, hybrid), register the ML-DSA-87 key, publish
//   node scripts/qday-public.mjs attack    sign with the published key alone: a Cosmos MsgSend, an EVM send
//
// npm run verify checks, every day, that the 5 QOR are still there and that the account has executed
// nothing but its own key registration (its sequence), whoever has tried since.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { JsonRpcProvider, Wallet, parseEther } from "ethers";
import { buildRegisterPqcKeyMsg, fetchPqcStatus, signProofOfPossession } from "@qorechain/sdk";
import { CHAIN_ID, EVM_CHAIN_ID, EVM_RPC, REST, account, bankSend, broadcast, ensureRoleKey, readDeployment, toUqor } from "../lib/chain.mjs";

const FILE = new URL("../runs/qday-public.json", import.meta.url);
const MALLORY = readDeployment().attacker, MALLORY_COSMOS = "qor1xle4mhhmsksk5rqn5ft8mat62pr553sfu97l9t";
const NET = /fetch failed|ETIMEDOUT|ECONNRESET|ENETUNREACH|EAI_AGAIN|socket hang up|timeout/i;
const clean = (e) => String(e?.message ?? e).replace(/\s+/g, " ").slice(0, 300);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const save = (o) => writeFileSync(FILE, JSON.stringify(o, null, 2) + "\n");

const cmd = process.argv[2];
if (cmd === "setup") {
  ensureRoleKey("qdaypublic");
  const pub = await account("qdaypublic"), o = await account("owner");
  const st = await fetchPqcStatus({ rest: REST, address: pub.cosmos });
  const out = existsSync(FILE) ? JSON.parse(readFileSync(FILE, "utf8")) : {};
  out.what = "an account whose secp256k1 private key is public, as if Shor had broken it; its ML-DSA-87 key is not";
  out.address = pub.cosmos; out.evmAddress = pub.evmAddr;
  if (!st.registered) {
    const f = await broadcast(o, [bankSend(o.cosmos, pub.cosmos, toUqor("5"))], "leash: Shor's gift, 5 QOR");
    if (f.code) throw new Error(`fund: code ${f.code} ${f.rawLog}`);
    out.fundTx = f.transactionHash; console.log("funded 5 QOR", f.transactionHash);
    await sleep(6000);
    const pop = signProofOfPossession({ chainId: CHAIN_ID, account: pub.cosmos, keypair: pub.pqc });
    const r = await broadcast(pub, [buildRegisterPqcKeyMsg(pub.cosmos, { pqcKeypair: pub.pqc, proofOfPossession: pop })], "leash: Shor's gift, register ML-DSA-87", "classical");
    if (r.code) throw new Error(`register: code ${r.code} ${r.rawLog}`);
    out.registerTx = r.transactionHash; console.log("ML-DSA-87 key registered", r.transactionHash);
    await sleep(6000);
  }
  // only now, with the ML-DSA-87 key on chain, is the classical key published
  out.secp256k1PrivateKey = pub.privateKey.startsWith?.("0x") ? pub.privateKey : "0x" + Buffer.from(pub.privateKey).toString("hex");
  save(out); console.log(`published: ${out.address} ${out.evmAddress}\nprivate key ${out.secp256k1PrivateKey}`);
} else if (cmd === "attack") {
  const out = JSON.parse(readFileSync(FILE, "utf8"));
  const pub = await account("qdaypublic");
  if (pub.cosmos !== out.address) throw new Error("keys file and runs/qday-public.json disagree");
  out.attempts = [];
  // 1. Cosmos lane: a MsgSend of all 5 QOR, signed with the published key only
  for (let i = 0; ; i++) {
    try { const r = await broadcast(pub, [bankSend(pub.cosmos, MALLORY_COSMOS, toUqor("5"))], "Shor's gift: take it", "classical"); out.attempts.push({ lane: "cosmos", label: "MsgSend 5 QOR to the attacker", refused: r.code !== 0, why: r.code ? `code ${r.code}: ${r.rawLog}` : "EXECUTED", tx: r.transactionHash }); break; }
    catch (e) { const why = clean(e); if (NET.test(why) && i < 5) { await sleep(5000); continue; } out.attempts.push({ lane: "cosmos", label: "MsgSend 5 QOR to the attacker", refused: true, why }); break; }
  }
  // 2. EVM lane: an ordinary signed transaction, exactly what the attack lab sends from a browser
  const w = new Wallet(out.secp256k1PrivateKey, new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID, { staticNetwork: true }));
  for (let i = 0; ; i++) {
    try { const t = await w.sendTransaction({ to: MALLORY, value: parseEther("4"), gasLimit: 21_000 }); const rc = await t.wait(); out.attempts.push({ lane: "evm", label: "send 4 QOR to the attacker", refused: rc.status !== 1, why: rc.status === 1 ? "EXECUTED" : "reverted", tx: t.hash }); break; }
    catch (e) { const why = clean(e.error?.message ?? e.info?.error?.message ?? e.shortMessage ?? e); if (NET.test(why) && i < 5) { await sleep(5000); continue; } out.attempts.push({ lane: "evm", label: "send 4 QOR to the attacker", refused: true, why }); break; }
  }
  out.attackedAt = new Date().toISOString();
  for (const a of out.attempts) console.log(`${a.refused ? "REFUSED " : "EXECUTED"} ${a.lane.padEnd(6)} ${a.label}\n          ${a.why.slice(0, 200)}`);
  save(out);
} else {
  console.log("usage: node scripts/qday-public.mjs setup|attack");
}
