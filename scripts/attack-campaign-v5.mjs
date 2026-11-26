// A randomized attack campaign against the live InvoiceDeskV5 (runs/live/desk.json), by dry run (eth_call)
// as the agent account: it costs nothing and changes nothing, and the desk answers exactly as it would to a
// real transaction, both ML-DSA-87 checks included. Two attackers, attacks from a seeded generator:
//
//   invoice:*   a compromised agent WITH its signer (it signs whatever it asks): one field of a genuine
//               invoice changed (amount, currency, vendor, payer, due date, id, a signature bit, the
//               signature's length, the caller, native QOR). The agent's signature is valid for what it
//               sends, so only the vendor's ML-DSA-87 signature and the desk's rules stand in the way.
//   agentsig:*  someone with the agent's classical key but not its signer (after Q-Day, or a stolen agent
//               host), holding signatures the signer made for OTHER payments: the genuine invoice, with no
//               agent signature, a flipped bit, random bytes, a fresh ML-DSA-87 key's or the vendor's
//               signature, or the signer's signature over a different amount, vendor, id, token, agent,
//               payer, desk or chain; and what V5 adds: a signature past its deadline, one whose deadline
//               the calldata moves, one made for the same invoice with another due date or another
//               vendor signature (a forged copy), and a V4-style signature for these very fields.
//
//   LEASH_DIR=<keys: vendor, agentsigner> node scripts/attack-campaign-v5.mjs [count=2000] [seed=20261127]
// writes runs/campaign-v5.json (outcomes) and runs/campaign-v5-sample.json (40 attacks as full calldata,
// which `npm run verify` asks the live desk again, with no keys).
import { readFileSync, writeFileSync } from "node:fs";
import { AbiCoder, Interface, JsonRpcProvider, getAddress, getBytes, hexlify, keccak256, toUtf8Bytes } from "ethers";
import { generatePqcKeypair, pqcSign } from "@qorechain/sdk";
import { rng } from "./attack-campaign.mjs";

const ROOT = new URL("../", import.meta.url);
process.env.LEASH_DEPLOYMENT ??= new URL("runs/live/desk.json", ROOT).pathname;
const { account } = await import("../lib/chain.mjs");
const { signInvoiceV2, agentMessageV4, agentMessageV5, FUSD } = await import("../lib/invoices.mjs");
const desk = new Interface(JSON.parse(readFileSync(new URL("build/InvoiceDeskV5.json", ROOT), "utf8")).abi);
const provider = new JsonRpcProvider(process.env.QORE_EVM_RPC ?? "https://evm-testnet.qore.host", 9800, { staticNetwork: true });
const randHex = (r, bytes) => "0x" + Array.from({ length: bytes }, () => Math.floor(r() * 256).toString(16).padStart(2, "0")).join("");

const N = Number(process.argv[2] ?? 2000), SEED = Number(process.argv[3] ?? 20261127);
const d = JSON.parse(readFileSync(process.env.LEASH_DEPLOYMENT, "utf8")).v2;
if (d.version !== 5) throw new Error("not an InvoiceDeskV5");
const v = await account("vendor"), signer = await account("agentsigner");
const dueBy = Math.floor(Date.parse("2027-06-30T23:59:59Z") / 1000);
const g = signInvoiceV2(v, { desk: d.invoiceDesk, payer: d.payerEvm, vendor: v.evmAddr, token: FUSD, fusd: "1", ref: `CAMPAIGN-V5-GENUINE-${Date.now().toString(36).toUpperCase()}`, dueBy });
// what the signer signs on V5: this desk, payer and agent, the invoice (as sent), and a deadline
const VALID = Math.floor(Date.now() / 1000) + 3 * 3600; // the campaign's deadline: ahead of every dry run
const agentFields = (a) => ({ desk: a.desk ?? d.invoiceDesk, payer: a.payer, agent: a.from, invoice: { vendor: a.vendor, token: a.token, amount: a.amount, id: a.id, dueBy: a.dueBy, signature: a.signature }, validUntil: a.validUntil ?? VALID });
const sigOver = (sk, f, chainId) => hexlify(pqcSign(sk, agentMessageV5({ ...f, ...(chainId ? { chainId } : {}) })));
const fresh = generatePqcKeypair();

function attack(i) {
  const r = rng(SEED * 1_000_003 + i);
  const inv = ["amount", "token", "vendor", "payer", "dueBy", "id", "sigbit", "siglen", "caller", "native"];
  const ag = ["none", "bitflip", "random", "freshkey", "vendorkey", "amount", "vendor", "id", "token", "agent", "payer", "desk", "chain", "expired", "deadline", "dueBy", "vendorsig", "v4style"];
  const family = r() < 0.5 ? "invoice" : "agentsig";
  const k = family === "invoice" ? inv[Math.floor(r() * inv.length)] : ag[Math.floor(r() * ag.length)];
  const a = { kind: `${family}:${k}`, from: d.agentAccountEvm, payer: d.payerEvm, token: g.token, vendor: g.vendor, amount: BigInt(g.amount), id: g.id, dueBy: g.dueBy, signature: g.signature, value: 0n, validUntil: VALID };
  if (family === "invoice") {
    if (k === "amount") { a.amount = BigInt(Math.floor(r() * 10_000_000)); if (a.amount === BigInt(g.amount)) a.amount += 1n; }
    if (k === "token") a.token = getAddress(randHex(r, 20));
    if (k === "vendor") a.vendor = getAddress(randHex(r, 20));
    if (k === "payer") a.payer = getAddress(randHex(r, 20));
    if (k === "dueBy") a.dueBy = g.dueBy + 1 + Math.floor(r() * 1e7);
    if (k === "id") a.id = randHex(r, 32);
    if (k === "sigbit") { const b = Buffer.from(g.signature.slice(2), "hex"); const p = Math.floor(r() * b.length); b[p] ^= 1 << Math.floor(r() * 8); a.signature = "0x" + b.toString("hex"); }
    if (k === "siglen") a.signature = randHex(r, Math.floor(r() * 6000));
    if (k === "caller") a.from = getAddress(randHex(r, 20));
    if (k === "native") { a.token = "0x0000000000000000000000000000000000000000"; a.value = a.amount; }
    a.agentSignature = sigOver(signer.pqc.secretKey, agentFields(a)); // the compromised agent's signer signs what it sends
  } else {
    const good = agentFields(a);
    if (k === "none") a.agentSignature = "0x";
    if (k === "bitflip") { const b = Buffer.from(sigOver(signer.pqc.secretKey, good).slice(2), "hex"); const p = Math.floor(r() * b.length); b[p] ^= 1 << Math.floor(r() * 8); a.agentSignature = "0x" + b.toString("hex"); }
    if (k === "random") a.agentSignature = randHex(r, Math.floor(r() * 6000));
    if (k === "freshkey") a.agentSignature = sigOver(fresh.secretKey, good);
    if (k === "vendorkey") a.agentSignature = sigOver(v.pqc.secretKey, good);
    const inv = (o) => ({ ...good, invoice: { ...good.invoice, ...o } });
    if (k === "amount") a.agentSignature = sigOver(signer.pqc.secretKey, inv({ amount: good.invoice.amount + 1n + BigInt(Math.floor(r() * 1e6)) }));
    if (k === "vendor") a.agentSignature = sigOver(signer.pqc.secretKey, inv({ vendor: getAddress(randHex(r, 20)) }));
    if (k === "id") a.agentSignature = sigOver(signer.pqc.secretKey, inv({ id: randHex(r, 32) }));
    if (k === "token") a.agentSignature = sigOver(signer.pqc.secretKey, inv({ token: getAddress(randHex(r, 20)) }));
    if (k === "expired") { a.validUntil = Math.floor(Date.now() / 1000) - 1 - Math.floor(r() * 1e6); a.agentSignature = sigOver(signer.pqc.secretKey, { ...good, validUntil: a.validUntil }); }
    if (k === "deadline") { a.agentSignature = sigOver(signer.pqc.secretKey, good); a.validUntil = VALID + 1 + Math.floor(r() * 1e6); }
    if (k === "dueBy") a.agentSignature = sigOver(signer.pqc.secretKey, inv({ dueBy: g.dueBy + 1 + Math.floor(r() * 1e7) }));
    if (k === "vendorsig") { const b = Buffer.from(g.signature.slice(2), "hex"); b[Math.floor(r() * b.length)] ^= 1 << Math.floor(r() * 8); a.agentSignature = sigOver(signer.pqc.secretKey, inv({ signature: "0x" + b.toString("hex") })); }
    if (k === "v4style") a.agentSignature = hexlify(pqcSign(signer.pqc.secretKey, agentMessageV4({ desk: d.invoiceDesk, payer: a.payer, agent: a.from, vendor: a.vendor, token: a.token, amount: a.amount, id: a.id })));
    if (k === "agent") a.agentSignature = sigOver(signer.pqc.secretKey, { ...good, agent: getAddress(randHex(r, 20)) });
    if (k === "payer") a.agentSignature = sigOver(signer.pqc.secretKey, { ...good, payer: getAddress(randHex(r, 20)) });
    if (k === "desk") a.agentSignature = sigOver(signer.pqc.secretKey, { ...good, desk: getAddress(randHex(r, 20)) });
    if (k === "chain") a.agentSignature = sigOver(signer.pqc.secretKey, good, 9800 + 1 + Math.floor(r() * 1000));
  }
  return a;
}
const calldata = (a) => desk.encodeFunctionData("pay", [a.payer, a.token, a.vendor, a.amount, a.id, a.dueBy, a.signature, a.agentSignature, a.validUntil ?? VALID]);
export async function askV4(from, to, data, value = 0n) {
  for (let i = 0; ; i++) {
    try { await provider.call({ from, to, data, value }); return "PAID"; }
    catch (e) {
      const raw = e.data ?? e.info?.error?.data;
      try { const n = desk.parseError(raw)?.name; if (n) return n; } catch { /* not a desk error */ }
      if (/insufficient funds|insufficient balance/i.test(e.shortMessage ?? e.message ?? "")) return "InsufficientFunds";
      if (raw === "0x" || /execution reverted/i.test(e.shortMessage ?? "")) return "Reverted";
      if (i >= 4) return `network: ${e.shortMessage ?? e.message}`;
      await new Promise((res) => setTimeout(res, 1500 * (i + 1)));
    }
  }
}

const controlData = calldata({ ...g, from: d.agentAccountEvm, payer: d.payerEvm, amount: BigInt(g.amount), agentSignature: sigOver(signer.pqc.secretKey, agentFields({ ...g, from: d.agentAccountEvm, payer: d.payerEvm, amount: BigInt(g.amount) })) });
const control = await askV4(d.agentAccountEvm, d.invoiceDesk, controlData);
const classicalAlone = await askV4(d.agentAccountEvm, d.invoiceDesk, calldata({ ...g, payer: d.payerEvm, amount: BigInt(g.amount), agentSignature: "0x" }));
if (control !== "PAID") throw new Error(`control: the genuine invoice with the agent's signature should pass, got ${control}`);
const outcomes = new Array(N), sample = [];
let next = 0;
await Promise.all(Array.from({ length: 6 }, async () => {
  for (let i; (i = next++) < N;) {
    const a = attack(i), data = calldata(a);
    outcomes[i] = [a.kind, await askV4(a.from, d.invoiceDesk, data, a.value)];
    if (i % 50 === 0) sample.push({ i, kind: a.kind, from: a.from, value: a.value.toString(), data, outcome: outcomes[i][1] });
    if (i % 250 === 0) console.log(`${i}/${N}`);
  }
}));
const hist = {};
for (const [k, o] of outcomes) (hist[k] ??= {})[o] = (hist[k][o] ?? 0) + 1;
const paid = outcomes.filter(([, o]) => o === "PAID").length, net = outcomes.filter(([, o]) => o.startsWith("network")).length;
const agentsigAll = outcomes.filter(([k]) => k.startsWith("agentsig:")), agentsigBad = agentsigAll.filter(([, o]) => o === "BadAgentSignature").length, agentsigExpired = agentsigAll.filter(([, o]) => o === "AgentSignatureExpired").length;
writeFileSync(new URL("runs/campaign-v5.json", ROOT), JSON.stringify({
  what: "randomized attack campaign against the live InvoiceDeskV5, as the agent account, by eth_call: a compromised agent with its signer (invoice:*), and the agent's classical key without its signer (agentsig:*)",
  desk: d.invoiceDesk, genuine: g, at: new Date().toISOString(), seed: SEED, count: N, control, classicalAlone, paid, network: net,
  agentsig: { count: agentsigAll.length, badAgentSignature: agentsigBad, agentSignatureExpired: agentsigExpired }, byKind: hist, outcomes: outcomes.map(([, o]) => o) }, null, 1) + "\n");
sample.sort((x, y) => x.i - y.i);
writeFileSync(new URL("runs/campaign-v5-sample.json", ROOT), JSON.stringify({ what: "every 50th attack of runs/campaign-v5.json as full calldata, and the signed genuine control, for npm run verify to ask the live desk again with no keys", desk: d.invoiceDesk, seed: SEED, control: { from: d.agentAccountEvm, data: controlData }, sample }) + "\n");
console.log(`control (genuine, signed): ${control}; classical key alone: ${classicalAlone}\n${N} attacks: ${paid} paid, ${net} network errors; agentsig ${agentsigAll.length}: ${agentsigBad} BadAgentSignature, ${agentsigExpired} AgentSignatureExpired`);
for (const [k, h] of Object.entries(hist).sort()) console.log(`  ${k.padEnd(18)} ${JSON.stringify(h)}`);
