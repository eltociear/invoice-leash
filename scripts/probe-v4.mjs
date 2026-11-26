// Probe: InvoiceDeskV4 on the live agent's desk. A genuine invoice from the vendor, relayed as the agent:
//   1. with the agent's classical (ed25519) key alone, no ML-DSA-87 signature   -> expected: BadAgentSignature
//   2. the same, with the agent signer's ML-DSA-87 signature                     -> expected: paid
// Runs with only the keys the live agent's CI holds. Writes runs/probes/v4-agent-sig.json.
//   LEASH_DIR=<CI-style keys dir> node scripts/probe-v4.mjs
import { writeFileSync } from "node:fs";
const ROOT = new URL("../", import.meta.url);
process.env.LEASH_DEPLOYMENT ??= new URL("runs/live/desk-v4.json", ROOT).pathname;
const { account, readDeployment } = await import("../lib/chain.mjs");
const { signInvoiceV2, FUSD } = await import("../lib/invoices.mjs");
const { executeV2 } = await import("../lib/agent.mjs");
const d = readDeployment().v2;
if (d.version !== 4) throw new Error("runs/live/desk-v4.json is not an InvoiceDeskV4");
const vendor = await account("vendor"), ref = `PROBE-V4-${Date.now().toString(36).toUpperCase()}`;
const inv = signInvoiceV2(vendor, { desk: d.invoiceDesk, payer: d.payerEvm, vendor: vendor.evmAddr, token: FUSD, fusd: "1", ref, dueBy: Math.floor(Date.now() / 1000) + 30 * 86400 });
const inbox = [{ from: "billing@dailyhosting.example", subject: `Invoice ${ref}`, body: "probe", invoice: inv }];
const out = { what: "InvoiceDeskV4: the agent's classical key alone vs. with its ML-DSA-87 signature", desk: d.invoiceDesk, invoice: inv, steps: [] };
for (const [label, step] of [["the agent's classical key alone (no ML-DSA-87 signature)", { item: 0, action: "pay", withoutAgentSignature: true }], ["with the agent signer's ML-DSA-87 signature", { item: 0, action: "pay" }]]) {
  const r = await executeV2(step, inbox, d);
  out.steps.push({ label, ok: r.ok, why: r.why, link: r.link });
  console.log(`${r.ok ? "PAID    " : "REFUSED "} ${label}\n         ${r.ok ? r.link : r.why}  ${r.ok ? "" : r.link ?? ""}`);
}
writeFileSync(new URL("runs/probes/v4-agent-sig.json", ROOT), JSON.stringify(out, null, 1) + "\n");
