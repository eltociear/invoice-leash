// A genuine invoice for the live InvoiceDeskV5, signed by its approved vendor and kept unpaid on purpose: the attack
// lab (§8) and npm run verify ask the desk about it, as the agent (classical key alone, a signature by another
// ML-DSA-87 key, a signature past its deadline) and as the company. Nothing is sent.
//   LEASH_DIR=<the live vendor's keys> node scripts/v5-lab-invoice.mjs     writes runs/live/v5-lab-invoice.json
import { writeFileSync } from "node:fs";
const ROOT = new URL("../", import.meta.url);
process.env.LEASH_DEPLOYMENT ??= new URL("runs/live/desk.json", ROOT).pathname;
const { account, readDeployment } = await import("../lib/chain.mjs");
const { signInvoiceV2, FUSD } = await import("../lib/invoices.mjs");
const d = readDeployment().v2;
if (d.version !== 5) throw new Error("not an InvoiceDeskV5");
const vendor = await account("vendor");
const invoice = signInvoiceV2(vendor, { desk: d.invoiceDesk, payer: d.payerEvm, vendor: vendor.evmAddr, token: FUSD, fusd: "3", ref: "LAB-V5-GENUINE", dueBy: 1814399999 });
writeFileSync(new URL("runs/live/v5-lab-invoice.json", ROOT), JSON.stringify({
  what: "a genuine invoice for the live agent's InvoiceDeskV5, kept unpaid on purpose: the attack lab (§8) and npm run verify ask the desk about it, as the agent without its signer's ML-DSA-87 signature, with another key's, with one past its deadline, and as the company",
  desk: d.invoiceDesk, payer: d.payerEvm, agent: d.agentAccountEvm, invoice }, null, 1) + "\n");
console.log(invoice.ref, invoice.vendor, invoice.id);
