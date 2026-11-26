// Probe: what InvoiceDeskV5's agent signature binds, on the live agent's desk, every attempt relayed for real.
// On V4 the agent's ML-DSA-87 signature covered vendor, token, amount and invoice id only, with no deadline. V5's
// covers the whole invoice (its digest, the due date included), the vendor's signature (its hash) and a deadline.
// One genuine 1 fUSD invoice A from the desk's vendor, and as the agent:
//   1. A with the agent's classical key alone (no ML-DSA-87 signature)                 -> BadAgentSignature
//   2. A with a signature made by the signer, but whose deadline has passed             -> AgentSignatureExpired
//   3. A with the signer's signature for a FORGED copy of A (same fields, a signature
//      not by the vendor; a signer that signs what it is asked, as in the compromised
//      run): on V4 this signature would pay A                                           -> BadAgentSignature
//   4. A's REISSUE (same id, a later due date, signed by the vendor), with the signer's
//      signature for A: on V4 it would pay the reissue                                  -> BadAgentSignature
//   5. A with the signer's signature, deadline 15 minutes ahead                         -> paid
//   6. the same calldata again                                                          -> AlreadyPaid
// Then the reissue's own signed payment is refused too (AlreadyPaid: one id, one payment).
//   LEASH_DIR=<keys: gas, agent, agentsigner, vendor> node scripts/probe-v5.mjs   writes runs/probes/v5-bindings.json
import { writeFileSync } from "node:fs";
import { generatePqcKeypair, pqcSign } from "@qorechain/sdk";
const ROOT = new URL("../", import.meta.url);
process.env.LEASH_DEPLOYMENT ??= new URL("runs/live/desk.json", ROOT).pathname;
const { account, readDeployment } = await import("../lib/chain.mjs");
const { signInvoiceV2, invoiceMessageV2, signAgentPayV5, FUSD } = await import("../lib/invoices.mjs");
const { executeV2, isPaid } = await import("../lib/agent.mjs");
const d = readDeployment().v2;
if (d.version !== 5) throw new Error("not an InvoiceDeskV5");
const vendor = await account("vendor"), signer = await account("agentsigner");
const series = Date.now().toString(36).toUpperCase(), due = Math.floor(Date.now() / 1000) + 30 * 86400;
const A = signInvoiceV2(vendor, { desk: d.invoiceDesk, payer: d.payerEvm, vendor: vendor.evmAddr, token: FUSD, fusd: "1", ref: `PROBE-V5-${series}`, dueBy: due });
const evil = generatePqcKeypair();
const forged = { ...A, signature: "0x" + Buffer.from(pqcSign(evil.secretKey, invoiceMessageV2({ desk: d.invoiceDesk, payer: d.payerEvm, vendor: A.vendor, token: A.token, amount: BigInt(A.amount), id: A.id, dueBy: A.dueBy }))).toString("hex") };
const reissue = signInvoiceV2(vendor, { desk: d.invoiceDesk, payer: d.payerEvm, vendor: vendor.evmAddr, token: FUSD, fusd: "1", ref: `PROBE-V5-${series}`, dueBy: due + 86400 });
const now = () => Math.floor(Date.now() / 1000);
const sig = (invoice, validUntil) => ({ signature: signAgentPayV5(signer, { desk: d.invoiceDesk, payer: d.payerEvm, agent: d.agentAccountEvm, invoice, validUntil }), validUntil });
const inbox = [{ subject: "A", invoice: A }, { subject: "A reissued, later due date", invoice: reissue }];
const out = { what: "InvoiceDeskV5 on the live desk: what the agent's ML-DSA-87 signature binds (the whole invoice, the vendor's signature, a deadline)", desk: d.invoiceDesk, invoice: A, reissue, steps: [] };
out.unpaidBefore = !(await isPaid(d, A));
if (!out.unpaidBefore) throw new Error("A is already paid");
const good = sig(A, now() + 900);
const steps = [
  ["A, the agent's classical key alone (no ML-DSA-87 signature)", { item: 0, action: "pay", withoutAgentSignature: true }, "BadAgentSignature"],
  ["A, a signer's signature whose deadline has passed", { item: 0, action: "pay", agentSignature: sig(A, now() - 120) }, "AgentSignatureExpired"],
  ["A, with the signer's signature for a forged copy of A (on V4 it would pay A)", { item: 0, action: "pay", agentSignature: sig(forged, now() + 900) }, "BadAgentSignature"],
  ["A's reissue (later due date, signed by the vendor), with the signature for A (on V4 it would pay)", { item: 1, action: "pay", agentSignature: good }, "BadAgentSignature"],
  ["A, with the signer's signature (deadline 15 minutes ahead)", { item: 0, action: "pay", agentSignature: good }, "PAID"],
  ["the same calldata again", { item: 0, action: "pay", agentSignature: good }, "AlreadyPaid"],
  ["A's reissue, with its own signature: one id, one payment", { item: 1, action: "pay", agentSignature: sig(reissue, now() + 900) }, "AlreadyPaid"],
];
for (const [label, step, expect] of steps) {
  const r = await executeV2(step, inbox, d);
  const got = r.ok ? "PAID" : (r.why ?? "").replace(/^InvoiceDesk: /, "");
  out.steps.push({ label, expect, ok: r.ok, why: r.why, link: r.link, as_expected: got === expect });
  console.log(`${got === expect ? "as expected" : "UNEXPECTED "}  ${r.ok ? "PAID    " : "REFUSED "} ${label}\n             ${r.ok ? r.link : r.why}  ${r.ok ? "" : r.link ?? ""}`);
}
out.at = new Date().toISOString();
writeFileSync(new URL("runs/probes/v5-bindings.json", ROOT), JSON.stringify(out, null, 1) + "\n");
if (out.steps.some((s) => !s.as_expected)) process.exitCode = 1;
