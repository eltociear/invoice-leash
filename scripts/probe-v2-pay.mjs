// Probe: the agent, acting as its own empty account, pays a fresh 1 fUSD genuine invoice through
// InvoiceDeskV2; the fUSD leaves the PAYER's account via the desk's allowance.
import { executeV2 } from "../lib/agent.mjs";
import { account, readDeployment } from "../lib/chain.mjs";
import { signInvoiceV2 } from "../lib/invoices.mjs";
const d = readDeployment().v2, vA = await account("vendorA");
const inv = signInvoiceV2(vA, { desk: d.invoiceDesk, payer: d.payerEvm, vendor: vA.evmAddr, fusd: process.argv[2] ?? "1", ref: `PROBE-${Date.now()}`, dueBy: Math.floor(Date.now() / 1000) + 86400 });
const r = await executeV2({ action: "pay", invoice: inv }, [], d);
console.log(JSON.stringify({ ref: inv.ref, fusd: inv.fusd, ok: r.ok, why: r.why ?? null, link: r.link ?? null }));
