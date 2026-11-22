// Offline, no keys needed: invoices verify with the vendor's ML-DSA-87 key, and fail on every
// tampering the demo uses plus the ones it does not. Uses throwaway accounts made here.
// (The real, on-chain version of this is `npm run verify`.)
import { deriveUnifiedAccount, generateMnemonic, pqcVerify, qorToEvm } from "@qorechain/sdk";
import { buildInbox, invoiceMessage } from "../lib/invoices.mjs";

const fresh = async () => { const a = await deriveUnifiedAccount(generateMnemonic(256), 0); a.evmAddr = qorToEvm(a.cosmos); return a; };
const [owner, vendorA, vendorB, attacker, otherPayer] = await Promise.all([1, 2, 3, 4, 5].map(fresh));
const desk = "0x000000000000000000000000000000000000dEaD";
const inbox = buildInbox({ desk, owner, vendorA, vendorB, attacker });
const keyOf = { [vendorA.evmAddr]: vendorA, [vendorB.evmAddr]: vendorB, [attacker.evmAddr]: attacker };
const sig = (v) => Buffer.from(v.signature.slice(2), "hex");
const check = (v, over = {}, s = sig(v)) => pqcVerify(keyOf[over.vendor ?? v.vendor].pqc.publicKey,
  invoiceMessage({ desk, payer: owner.evmAddr, vendor: v.vendor, amountWei: BigInt(v.amountWei), id: v.id, dueBy: v.dueBy, ...over }), s);

let fail = 0;
const t = (cond, msg) => { console.log(`${cond ? "ok  " : "FAIL"} ${msg}`); if (!cond) fail++; };

console.log("the demo inbox:");
for (const [i, m] of inbox.entries()) {
  if (!m.invoice) continue;
  const ok = check(m.invoice);
  const want = !/signed by Hostline|changed after signing/.test(m.expect);
  t(ok === want, `[${i}] signature ${ok ? "valid" : "invalid"}  (${m.expect})`);
}

console.log("tampering with a genuine invoice (each must fail):");
const g = inbox[0].invoice;
const flipped = sig(g); flipped[100] ^= 1;
t(!check(g, {}, flipped), "one bit of the signature flipped");
t(!check(g, { amountWei: BigInt(g.amountWei) + 1n }), "amount + 1 wei");
t(!check(g, { dueBy: g.dueBy + 86400 }), "due date + 1 day");
t(!check(g, { payer: otherPayer.evmAddr }), "charged to another payer");
t(!check(g, { desk: "0x000000000000000000000000000000000000bEEF" }), "presented to another desk");
t(!check(g, { vendor: vendorB.evmAddr }), "claimed by the other vendor (checked with its key)");
t(invoiceMessage({ desk, payer: owner.evmAddr, vendor: g.vendor, amountWei: BigInt(g.amountWei), id: g.id, dueBy: g.dueBy }).length === 256, "signed message is 256 bytes (domain, chain id, desk, payer, vendor, amount, id, due)");
t(sig(g).length === 4627 && vendorA.pqc.publicKey.length === 2592, "ML-DSA-87 sizes: signature 4627, public key 2592");

process.exit(fail ? 1 : 0);
