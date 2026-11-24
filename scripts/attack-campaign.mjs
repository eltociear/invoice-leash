// A randomized attack campaign against the live InvoiceDeskV3 (the live agent's desk, runs/live/desk.json).
// Every attack is a dry run (eth_call) as the agent account: it costs nothing and changes nothing, and the
// desk answers exactly as it would to a real transaction, ML-DSA-87 precompile included.
//
// From one genuine invoice, each attack changes one thing at random (amount, currency, vendor, payer,
// due date, invoice id, a signature bit, the signature's length, the caller, native QOR instead of fUSD),
// plus signed attacks: forgeries with fresh ML-DSA-87 keys, a genuine invoice over the agent's limit,
// a zero amount, a valid invoice from an unapproved vendor. Attacks come from a seeded generator, so
// `npm run verify` regenerates a sample and asks the live desk again.
//
//   node scripts/attack-campaign.mjs [count=2000] [seed=20261124]     writes runs/campaign.json
// Needs the live vendor's key only to sign the genuine invoice and the signed attacks (once).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { Interface, JsonRpcProvider, getAddress, hexlify, keccak256, toUtf8Bytes } from "ethers";

const ROOT = new URL("../", import.meta.url);
const OUT = new URL("runs/campaign.json", ROOT);
const desk = new Interface(JSON.parse(readFileSync(new URL("build/InvoiceDeskV3.json", ROOT), "utf8")).abi);
const provider = new JsonRpcProvider(process.env.QORE_EVM_RPC ?? "https://evm-testnet.qore.host", 9800, { staticNetwork: true });

/** mulberry32: a small seeded generator, so the same seed gives the same attacks anywhere. */
export function rng(seed) { let a = seed >>> 0; return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
const randHex = (r, bytes) => "0x" + Array.from({ length: bytes }, () => Math.floor(r() * 256).toString(16).padStart(2, "0")).join("");

/** Attack number i of a campaign, from the genuine invoice. Pure: the same (seed, i) always gives the same attack. */
export function attack(seed, i, g, d) {
  const r = rng(seed * 1_000_003 + i);
  const kinds = ["amount", "token", "vendor", "payer", "dueBy", "id", "sigbit", "siglen", "caller", "native"];
  const kind = kinds[Math.floor(r() * kinds.length)];
  const a = { kind, from: d.agentAccountEvm, payer: d.payerEvm, token: g.token, vendor: g.vendor, amount: BigInt(g.amount), id: g.id, dueBy: g.dueBy, signature: g.signature, value: 0n };
  if (kind === "amount") { a.amount = BigInt(Math.floor(r() * 10_000_000)); if (a.amount === BigInt(g.amount)) a.amount += 1n; }
  if (kind === "token") a.token = getAddress(randHex(r, 20));
  if (kind === "vendor") a.vendor = getAddress(randHex(r, 20));
  if (kind === "payer") a.payer = getAddress(randHex(r, 20));
  if (kind === "dueBy") a.dueBy = g.dueBy + 1 + Math.floor(r() * 1e7);
  if (kind === "id") a.id = randHex(r, 32);
  if (kind === "sigbit") { const b = Buffer.from(g.signature.slice(2), "hex"); const p = Math.floor(r() * b.length); b[p] ^= 1 << Math.floor(r() * 8); a.signature = "0x" + b.toString("hex"); }
  if (kind === "siglen") a.signature = randHex(r, Math.floor(r() * 6000));
  if (kind === "caller") a.from = getAddress(randHex(r, 20));
  if (kind === "native") { a.token = "0x0000000000000000000000000000000000000000"; a.value = a.amount; }
  return a;
}

export async function ask(a, d) {
  const data = desk.encodeFunctionData("pay", [a.payer, a.token, a.vendor, a.amount, a.id, a.dueBy, a.signature]);
  for (let i = 0; ; i++) {
    try { await provider.call({ from: a.from, to: d.invoiceDesk, data, value: a.value }); return "PAID"; }
    catch (e) {
      const raw = e.data ?? e.info?.error?.data;
      try { const n = desk.parseError(raw)?.name; if (n) return n; } catch { /* not a desk error */ }
      if (/insufficient funds|insufficient balance/i.test(e.shortMessage ?? e.message ?? "")) return "InsufficientFunds"; // value sent from an account that has none
      if (raw === "0x" || /execution reverted/i.test(e.shortMessage ?? "")) return "Reverted";
      if (i >= 4) return `network: ${e.shortMessage ?? e.message}`;
      await new Promise((res) => setTimeout(res, 1500 * (i + 1)));
    }
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const N = Number(process.argv[2] ?? 2000), SEED = Number(process.argv[3] ?? 20261124);
  process.env.LEASH_DEPLOYMENT ??= new URL("runs/live/desk.json", ROOT).pathname;
  const d = JSON.parse(readFileSync(process.env.LEASH_DEPLOYMENT, "utf8")).v2;
  let base = existsSync(OUT) ? JSON.parse(readFileSync(OUT, "utf8")) : null;
  if (!base || base.desk !== d.invoiceDesk) {
    // sign the genuine invoice and the signed attacks once, with the live vendor's key
    const { account } = await import("../lib/chain.mjs");
    const { signInvoiceV2, invoiceMessageV2, FUSD, toFusd } = await import("../lib/invoices.mjs");
    const { generatePqcKeypair, pqcSign } = await import("@qorechain/sdk");
    const v = await account("vendor"), dueBy = Math.floor(Date.parse("2027-06-30T23:59:59Z") / 1000);
    const sign = (o) => signInvoiceV2(v, { desk: d.invoiceDesk, payer: d.payerEvm, vendor: v.evmAddr, token: FUSD, dueBy, ...o });
    const genuine = sign({ fusd: "3", ref: "CAMPAIGN-GENUINE" });
    const forge = (k) => { const f = { desk: d.invoiceDesk, payer: d.payerEvm, vendor: v.evmAddr, token: FUSD, amount: toFusd("3"), id: keccak256(toUtf8Bytes(`CAMPAIGN-FORGED-${k}`)), dueBy };
      return { kind: "forged (fresh ML-DSA-87 key)", payer: d.payerEvm, token: FUSD, vendor: v.evmAddr, amount: f.amount.toString(), id: f.id, dueBy, signature: hexlify(pqcSign(generatePqcKeypair().secretKey, invoiceMessageV2(f))), expect: "BadSignature" }; };
    const big = sign({ fusd: "11", ref: "CAMPAIGN-OVER-LIMIT" }), zero = sign({ fusd: "0", ref: "CAMPAIGN-ZERO" });
    const mal = generatePqcKeypair(); // a valid key, but its "vendor" address is not approved
    const signed = [...Array.from({ length: 20 }, (_, k) => forge(k)),
      { kind: "genuine, over the agent's per-payment limit", ...big, payer: d.payerEvm, expect: "OverPerPaymentLimit" },
      { kind: "genuine, zero amount", ...zero, payer: d.payerEvm, expect: "ZeroAmount" },
      { kind: "unapproved vendor", payer: d.payerEvm, token: FUSD, vendor: "0x37F35dDeFb85A16A0c13A2567DF57a50474a4609", amount: toFusd("3").toString(), id: keccak256(toUtf8Bytes("CAMPAIGN-MALLORY")), dueBy, signature: hexlify(pqcSign(mal.secretKey, new Uint8Array(32))), expect: "UnknownVendor" }];
    base = { what: "randomized attack campaign against the live InvoiceDeskV3, as the agent account, by eth_call", desk: d.invoiceDesk, genuine, signed };
  }
  const g = base.genuine;
  const control = await ask({ from: d.agentAccountEvm, payer: d.payerEvm, token: g.token, vendor: g.vendor, amount: BigInt(g.amount), id: g.id, dueBy: g.dueBy, signature: g.signature, value: 0n }, d);
  if (control !== "PAID") throw new Error(`control: the genuine invoice should pass, got ${control}`);
  const outcomes = new Array(N);
  let next = 0;
  await Promise.all(Array.from({ length: 6 }, async () => { for (let i; (i = next++) < N;) { const a = attack(SEED, i, g, d); outcomes[i] = [a.kind, await ask(a, d)]; if (i % 250 === 0) console.log(`${i}/${N}`); } }));
  const signedOut = [];
  for (const s of base.signed) signedOut.push([s.kind, await ask({ from: d.agentAccountEvm, payer: s.payer, token: s.token, vendor: s.vendor, amount: BigInt(s.amount), id: s.id, dueBy: s.dueBy, signature: s.signature, value: 0n }, d), s.expect]);
  const hist = {};
  for (const [k, o] of outcomes) (hist[k] ??= {})[o] = (hist[k][o] ?? 0) + 1;
  const paid = outcomes.filter(([, o]) => o === "PAID").length + signedOut.filter(([, o]) => o === "PAID").length;
  const net = outcomes.filter(([, o]) => o.startsWith("network")).length;
  writeFileSync(OUT, JSON.stringify({ ...base, at: new Date().toISOString(), seed: SEED, count: N, control, paid, network: net, byKind: hist, signedOutcomes: signedOut, outcomes: outcomes.map(([, o]) => o) }, null, 1) + "\n");
  console.log(`control (genuine): ${control}\n${N} random attacks + ${signedOut.length} signed: ${paid} paid, ${net} network errors`);
  for (const [k, h] of Object.entries(hist)) console.log(`  ${k.padEnd(8)} ${JSON.stringify(h)}`);
  for (const [k, o, e] of signedOut.filter((x, i, a) => i === 0 || x[0] !== a[i - 1][0])) console.log(`  ${k}: ${o} (expected ${e})`);
}
