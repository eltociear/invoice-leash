// Builds docs/app-data.json for the Desk Console (docs/app.html + docs/app.js): the desks to watch, the
// contracts' ABIs and V3 bytecode, and the public test vendor. Offline: no network.
//   node scripts/app.mjs
import { readFileSync, writeFileSync } from "node:fs";

const root = new URL("../", import.meta.url);
const json = (p) => JSON.parse(readFileSync(new URL(p, root), "utf8"));
const v2 = json("build/InvoiceDeskV2.json"), v3 = json("build/InvoiceDeskV3.json"), v4 = json("build/InvoiceDeskV4.json");
const dep = json("deployment.json"), live = json("runs/live/desk.json").v2, own = json("runs/own-company-v3/desk.json").v2;
const pub = json("runs/public-vendor.json");
const liveLog = readFileSync(new URL("runs/live/log.jsonl", root), "utf8").trim().split("\n").filter(Boolean).map((l) => JSON.parse(l));
const ownCsv = readFileSync(new URL("runs/own-company-v3/payments.csv", root), "utf8").trim().split("\n").slice(1).map((l) => l.split(","));

const desk = (name, note, d, version, extra = {}) => ({ name, note, version, desk: d.invoiceDesk, payer: d.payerEvm, agent: d.agentAccountEvm, deployBlock: d.deployBlock ?? null, deployTx: d.deployTx ?? d.txs?.deploy ?? null, vendors: d.vendors ?? {}, ...extra });
const data = {
  chain: { chainId: 9800, name: "QoreChain testnet (qorechain-diana)", rpc: "https://evm-testnet.qore.host", explorer: "https://explore.qore.network/tx/", faucet: "https://dashboard.qorechain.io/faucet" },
  fusd: "0x97143B771D34ddb9130b807b135Ae675A5a963CA",
  desks: [
    desk("The live agent's desk", "InvoiceDeskV5: the agent's payments need its own ML-DSA-87 signature over the whole invoice, valid 15 minutes. A GitHub Actions job runs the agent here daily, with a decider that obeys every email.", live, live.version ?? 3, {
      agentPayments: [...liveLog.filter((r) => r.ok && r.at >= (live.deployedAt ?? "")).map((r) => ({ at: r.at, label: r.label, link: r.link })),
        ...json("runs/probes/v5-bindings.json").steps.filter((st) => st.ok).map((st) => ({ at: json("runs/probes/v5-bindings.json").at, label: `probe: ${st.label}`, link: st.link }))],
      refusals: liveLog.filter((r) => !r.ok && r.at >= (live.deployedAt ?? "")).length }),
    (() => { const v4 = json("runs/live/desk-v4.json").v2;
      return desk("The live agent's desk until 2026-11-26 (V4)", "InvoiceDeskV4: the compromised-agent run, the attack campaign and the window probe ran here. Kept deployed and unchanged.", v4, 4, {
        agentPayments: liveLog.filter((r) => r.ok && r.at >= (v4.deployedAt ?? "") && r.at < (live.deployedAt ?? "9")).map((r) => ({ at: r.at, label: r.label, link: r.link })) }); })(),
    (() => { const c = json("runs/own-company-v5/desk.json").v2, rows = readFileSync(new URL("runs/own-company-v5/payments.csv", root), "utf8").trim().split("\n").slice(1).map((l) => l.split(","));
      return desk("A company set up from nothing on V5", "InvoiceDeskV5, set up on 2026-11-27 with desk.mjs setup by following GETTING_STARTED.md: Lighthouse Analytics, one sealed invoice, one past due and one over the limit paid in person.", c, 5, {
        agentPayments: rows.filter((r) => r[7] === "agent").map((r) => ({ at: r[0], label: `${r[1]} ${r[3]}, ${r[5]} fUSD`, link: `https://explore.qore.network/tx/${r[8]}` })) }); })(),
    (() => { const c = json("runs/own-company-v4/desk.json").v2, rows = readFileSync(new URL("runs/own-company-v4/payments.csv", root), "utf8").trim().split("\n").slice(1).map((l) => l.split(","));
      return desk("A company set up from nothing on V4", "InvoiceDeskV4, set up with desk.mjs setup by following GETTING_STARTED.md; the Desk Console was driven in a browser on it.", c, 4, {
        agentPayments: rows.filter((r) => r[7] === "agent").map((r) => ({ at: r[0], label: `${r[1]} ${r[3]}, ${r[5]} fUSD`, link: `https://explore.qore.network/tx/${r[8]}` })) }); })(),
    desk("A company set up with desk.mjs", "InvoiceDeskV3, upgraded from V2 with desk.mjs upgrade. Three vendors, each with its own key.", own, 3, {
      agentPayments: ownCsv.filter((r) => r[7] === "agent" && r[9] === own.invoiceDesk).map((r) => ({ at: r[0], label: `${r[1]} ${r[3]}, ${r[5]} fUSD`, link: `https://explore.qore.network/tx/${r[8]}` })) }),
    desk("The demo company (v2)", "InvoiceDeskV2, the desk the recorded runs and the attack lab use.", { ...dep.v2, vendors: Object.fromEntries(Object.entries(dep.vendors).map(([k, v]) => [v, k])) }, 2),
  ],
  abiV2: v2.abi, abiV3: v3.abi, abiV4: v4.abi, abiV5: json("build/InvoiceDeskV5.json").abi,
  publicVendor: { address: pub.address, evm: pub.evmAddress, publicKey: pub.mlDsa87PublicKey, secretKey: pub.mlDsa87SecretKey, registerTx: pub.registerTx },
};
writeFileSync(new URL("docs/app-data.json", root), JSON.stringify(data) + "\n");
console.log(`docs/app-data.json: ${data.desks.length} desks, V3 bytecode ${(v3.bytecode.length - 2) / 2} bytes, public vendor ${pub.evmAddress}`);
