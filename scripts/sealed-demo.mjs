// Sealed invoices, live: the agent account publishes an ML-KEM-1024 key in QoreChain's KEM key registry
// (MsgRegisterKEMKey, signed by the account's human holder with the hybrid ML-DSA-87 key); Tokenwell seals
// a genuine, ML-DSA-87 signed invoice to it; Mallory seals a forged "Hostline" invoice to it too (anyone
// can seal to a public key). The agent opens both and asks InvoiceDeskV2: sealing kept them confidential,
// the signature still decides. Writes inbox/inbox-v2-SEALED.json and runs/sealed.json.
import { writeFileSync } from "node:fs";
import { Interface, JsonRpcProvider } from "ethers";
import { EVM_CHAIN_ID, EVM_RPC, account, broadcast, readDeployment } from "../lib/chain.mjs";
import { signInvoiceV2 } from "../lib/invoices.mjs";
import { deskV2 } from "../lib/agent.mjs";
import { agentKemKeys, describeEnvelope, kemKeyOf, openInvoice, registerKemMsg, sealInvoice } from "../lib/sealed.mjs";

const d = readDeployment().v2, aa = await account("agentacct"), o = await account("owner"), b = await account("vendorB"), mal = await account("attacker"), hostline = await account("vendorA");
const keys = agentKemKeys(), out = { account: aa.cosmos, steps: [] };
const st = await kemKeyOf(aa.cosmos).catch(() => ({ registered: false }));
if (!st.registered || Buffer.compare(Buffer.from(st.publicKey), Buffer.from(keys.mlkemPublicKey))) {
  const r = await broadcast(aa, [registerKemMsg(aa.cosmos, keys)], "leash: the agent's ML-KEM-1024 key, for sealed invoices");
  if (r.code) throw new Error(`register REFUSED code ${r.code}: ${r.rawLog}`);
  out.registerTx = r.transactionHash; console.log(`ML-KEM-1024 key registered for ${aa.cosmos}  ${r.transactionHash}`);
  await new Promise((r) => setTimeout(r, 6000));
}
const due = Math.floor(Date.parse("2027-06-30T23:59:59Z") / 1000);
const genuine = signInvoiceV2(b, { desk: d.invoiceDesk, payer: o.evmAddr, vendor: b.evmAddr, fusd: "20", ref: "TOKENWELL-INV-8810-SEALED", dueBy: due });
const forged = signInvoiceV2(mal, { desk: d.invoiceDesk, payer: o.evmAddr, vendor: hostline.evmAddr, fusd: "45", ref: "HOSTLINE-2026-12-0110-SEALED", dueBy: due });
const inbox = [
  { from: "accounts@tokenwell.example", subject: "Invoice TOKENWELL-INV-8810 (sealed)", body: "Our invoice is attached, sealed to your account's ML-KEM-1024 key.", sealed: await sealInvoice(aa.cosmos, genuine) },
  { from: "billing@hostline.example", subject: "Invoice HOSTLINE-2026-12-0110 (sealed)", body: "Sealed for your security. Please pay promptly.", sealed: await sealInvoice(aa.cosmos, forged) },
];
writeFileSync(new URL("../inbox/inbox-v2-SEALED.json", import.meta.url), JSON.stringify(inbox, null, 2) + "\n");
const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID, { staticNetwork: true });
const ask = async (inv, from) => { try { await provider.call({ from, to: d.invoiceDesk, data: deskV2.encodeFunctionData("pay", [o.evmAddr, inv.token, inv.vendor, inv.amount, inv.id, inv.dueBy, inv.signature]) }); return "WOULD PAY"; } catch (e) { try { return deskV2.parseError(e.data ?? e.info?.error?.data).name; } catch { return e.shortMessage; } } };
for (const [i, m] of inbox.entries()) {
  const inv = openInvoice(m.sealed, keys);
  const row = { email: i, envelope: describeEnvelope(m.sealed), opened: { ref: inv.ref, fusd: inv.fusd, vendor: inv.vendor, id: inv.id },
    asAgent: await ask(inv, aa.evmAddr), asCompany: await ask(inv, o.evmAddr) };
  out.steps.push(row); console.log(JSON.stringify(row));
}
writeFileSync(new URL("../runs/sealed.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
