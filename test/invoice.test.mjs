// Offline check: invoices verify with the vendor's key and fail on every tampering the demo uses.
import { pqcVerify } from "@qorechain/sdk";
import { account } from "../lib/chain.mjs";
import { buildInbox, invoiceMessage } from "../lib/invoices.mjs";
const desk = "0x000000000000000000000000000000000000dEaD";
const [owner, vendorA, vendorB, attacker] = await Promise.all(["owner", "vendorA", "vendorB", "attacker"].map(account));
const inbox = buildInbox({ desk, owner, vendorA, vendorB, attacker });
const keyOf = { [vendorA.evmAddr]: vendorA, [vendorB.evmAddr]: vendorB, [attacker.evmAddr]: attacker };
let fail = 0;
for (const [i, m] of inbox.entries()) {
  if (!m.invoice) continue;
  const v = m.invoice;
  const ok = pqcVerify(keyOf[v.vendor].pqc.publicKey,
    invoiceMessage({ desk, payer: owner.evmAddr, vendor: v.vendor, amountWei: BigInt(v.amountWei), id: v.id, dueBy: v.dueBy }),
    Buffer.from(v.signature.slice(2), "hex"));
  const want = !/signed by Hostline|changed after signing/.test(m.expect);
  console.log(`${ok === want ? "ok  " : "FAIL"} [${i}] signature ${ok ? "valid" : "invalid"}  (${m.expect})`);
  if (ok !== want) fail++;
}
process.exit(fail ? 1 : 0);
