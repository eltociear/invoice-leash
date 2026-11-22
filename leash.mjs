#!/usr/bin/env node
// leash.mjs - an invoice-paying AI agent that stays safe even when its model is fully compromised.
// QoreChain diana testnet only. Never prints key material.
//
//   node leash.mjs init                      create every demo key (owner, gas, agent, 2 vendors, attacker)
//   node leash.mjs whoami                    print the addresses; fund the OWNER from the faucet
//   node leash.mjs balance                   balances of every account
//   node leash.mjs register owner            register the owner's ML-DSA-87 key (once, before fund)
//   node leash.mjs fund                      owner pays fees money to gas, vendors and attacker
//   node leash.mjs register all              register every other account's ML-DSA-87 key
//   node leash.mjs deploy                    owner deploys InvoiceDesk and approves the two vendors
//   node leash.mjs link <perTx> <daily> [h]  owner links the agent: scoped to InvoiceDesk.pay, value-capped
//   node leash.mjs rules                     what the chain will enforce for the agent
//   node leash.mjs inbox                     vendors and attacker write the inbox (inbox/inbox.json)
//   node leash.mjs run [--compromised|--llm] the agent works through the inbox
//   node leash.mjs inbox <series> [dueDate]  the same inbox with new invoice numbers (inbox/inbox-<series>.json)
//   node leash.mjs new-agent                 a new agent key for the same owner (then link)
//   node leash.mjs fresh-owner              new owner + agent keys for a clean re-run (moves the money, same desk)
//   node leash.mjs topup [QOR]               owner refills the agent's gas wallet (fees only)
//   node leash.mjs plan [--llm]              what the decider WOULD do, without touching the chain
//   node leash.mjs approve <email>           a human pays an over-limit invoice the agent could not
//   node leash.mjs revoke                    owner switches the agent off in one transaction
//   node leash.mjs after-revoke              the agent tries one more honest payment
import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { Contract, ContractFactory, Interface, JsonRpcProvider, Wallet } from "ethers";
import {
  fetchPqcStatus, buildRegisterPqcKeyMsg, signProofOfPossession, signAuthenticatorLinkEd25519,
  linkAuthenticatorMsgs, revokeAuthenticatorMsg, fetchSpendingRules, fetchAuthenticators, fetchAuthNonce,
  openEvmWindowMsg, closeEvmWindowMsg, fetchEvmWindow,
} from "@qorechain/sdk";
import {
  CHAIN_ID, EVM_CHAIN_ID, EVM_RPC, REST, EXPLORER, ROLES, account, agentKey, balance, bankSend, broadcast,
  createKeys, rotateOwnerKeys, rotateAgentKey, accountFromKey, fmt, hex, onChain, readDeployment, toUqor, writeDeployment,
} from "./lib/chain.mjs";
import { buildInbox } from "./lib/invoices.mjs";

const INBOX = process.env.LEASH_INBOX ? new URL(process.env.LEASH_INBOX, `file://${process.cwd()}/`) : new URL("./inbox/inbox.json", import.meta.url);
const ART = JSON.parse(readFileSync(new URL("./build/InvoiceDesk.json", import.meta.url), "utf8"));
const loadInbox = () => JSON.parse(readFileSync(INBOX, "utf8"));
const need = (d, k, hint) => { if (!d[k]) throw new Error(`no ${k} yet: run "node leash.mjs ${hint}" first`); return d[k]; };

const cmds = {
  async init() {
    console.log(`keys saved in ${createKeys()} (mode 600, never in the repo)`);
    await cmds.whoami();
  },

  async whoami() {
    for (const r of ROLES) console.log(`${r.padEnd(9)} ${(await account(r)).cosmos}  ${(await account(r)).evmAddr}`);
    console.log(`agent     ed25519 ${hex(agentKey().pk).slice(0, 16)}...  (holds no money)`);
  },

  async balance() {
    for (const r of ROLES) { const a = await account(r); console.log(`${r.padEnd(9)} ${a.cosmos}  ${fmt(await balance(a.cosmos))}`); }
  },

  async register(who = "all") {
    const roles = who === "all" ? ROLES : [who];
    for (const r of roles) {
      const acc = await account(r);
      const st = await fetchPqcStatus({ rest: REST, address: acc.cosmos });
      if (st.registered) { console.log(`${r.padEnd(9)} ML-DSA-87 key already registered`); continue; }
      const pop = signProofOfPossession({ chainId: CHAIN_ID, account: acc.cosmos, keypair: acc.pqc });
      const msg = buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc, proofOfPossession: pop });
      const res = await broadcast(acc, [msg], "register ML-DSA-87 key", "classical");
      console.log(res.code === 0 ? `${r.padEnd(9)} ML-DSA-87 key registered  ${EXPLORER}${res.transactionHash}` : `${r}: REFUSED code ${res.code}: ${res.rawLog}`);
      if (res.code) process.exitCode = 1;
    }
  },

  async fund() {
    const o = await account("owner");
    const plan = { gas: "3", vendorA: "0.5", vendorB: "0.5", attacker: "0.5" };
    const msgs = [];
    for (const [r, q] of Object.entries(plan)) msgs.push(bankSend(o.cosmos, (await account(r)).cosmos, toUqor(q)));
    const res = await broadcast(o, msgs, "leash: fee money");
    console.log(res.code === 0 ? `funded ${Object.entries(plan).map(([r, q]) => `${r} ${q}`).join(", ")} QOR  ${EXPLORER}${res.transactionHash}` : `REFUSED code ${res.code}: ${res.rawLog}`);
    if (res.code) process.exitCode = 1;
  },

  async approveVendors(deskAddr) {
    const o = await account("owner"), a = await account("vendorA"), b = await account("vendorB");
    // Plain EVM transactions on QoreChain need an open window, granted by a hybrid-signed tx.
    const w = await fetchEvmWindow({ rest: REST, address: o.cosmos });
    if (!w.found) {
      const res = await broadcast(o, [openEvmWindowMsg({ sender: o.cosmos, blocks: 600, maxTxs: 4, maxValue: String(toUqor("3")) })], "leash: owner window");
      if (res.code) throw new Error(`open window REFUSED code ${res.code}: ${res.rawLog}`);
      console.log(`EVM window open (4 txs, 3 QOR incl. fees)  ${EXPLORER}${res.transactionHash}`);
    }
    const wallet = new Wallet(o.privateKey, new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID));
    let c;
    if (!deskAddr) {
      c = await new ContractFactory(ART.abi, ART.bytecode, wallet).deploy();
      await c.waitForDeployment();
      deskAddr = await c.getAddress();
      console.log(`InvoiceDesk deployed at ${deskAddr}  (tx ${c.deploymentTransaction().hash})`);
    } else c = new Contract(deskAddr, ART.abi, wallet);
    for (const v of [a, b]) {
      const tx = await c.approveVendor(v.evmAddr);
      await tx.wait();
      console.log(`owner approved vendor ${v.role} ${v.evmAddr}  (tx ${tx.hash})`);
    }
    const close = await broadcast(o, [closeEvmWindowMsg(o.cosmos)], "leash: close window");
    console.log(close.code === 0 ? "EVM window closed" : `close window: code ${close.code}`);
    writeDeployment({ ...readDeployment(), chainId: CHAIN_ID, evmChainId: EVM_CHAIN_ID, invoiceDesk: deskAddr,
      owner: o.cosmos, vendors: { Hostline: a.evmAddr, Tokenwell: b.evmAddr }, attacker: (await account("attacker")).evmAddr });
  },

  async deploy() { await cmds.approveVendors(); },

  async "fresh-owner"() {
    const deskAddr = need(readDeployment(), "invoiceDesk", "deploy");
    const prevName = rotateOwnerKeys();
    const prev = await accountFromKey(prevName), o = await account("owner");
    const bal = BigInt(await balance(prev.cosmos)), keep = toUqor("0.3");
    const res = await broadcast(prev, [bankSend(prev.cosmos, o.cosmos, bal - keep)], "leash: move to fresh owner");
    if (res.code) throw new Error(`move REFUSED code ${res.code}: ${res.rawLog}`);
    console.log(`moved ${fmt(bal - keep)} from ${prev.cosmos} to the new owner ${o.cosmos}`);
    await new Promise((s) => setTimeout(s, 6000));
    await cmds.register("owner");
    await cmds.approveVendors(deskAddr);
  },

  async link(perTx = "1", daily = "2.5", hours = "24") {
    const d = readDeployment(), deskAddr = need(d, "invoiceDesk", "deploy");
    const o = await account("owner"), k = agentKey();
    const paySel = new Interface(ART.abi).getFunction("pay").selector;
    const proof = signAuthenticatorLinkEd25519({ chainId: CHAIN_ID, account: o.cosmos, privateKey: k.sk });
    const msgs = linkAuthenticatorMsgs({
      owner: o.cosmos, chainId: CHAIN_ID, ...proof,
      permissions: ["evm"],
      expiryUnix: Math.floor(Date.now() / 1000) + Number(hours) * 3600,
      label: "leash invoice agent",
      spendingRule: {
        id: "leash", enabled: true, perTxLimit: String(toUqor(perTx)), dailyLimit: String(toUqor(daily)),
        allowedDenoms: ["uqor"], allowedEvmCalls: [`${deskAddr.toLowerCase()}/${paySel}`],
      },
    });
    const res = await broadcast(o, msgs, "leash: link agent");
    if (res.code) { console.log(`REFUSED code ${res.code}: ${res.rawLog}`); process.exitCode = 1; return; }
    const c = await onChain(res.transactionHash);
    console.log(`agent linked to ${o.cosmos}`);
    console.log(`  may do       EVM calls to InvoiceDesk.pay (${deskAddr}/${paySel}) and nothing else`);
    console.log(`  per payment  ${perTx} QOR   per day ${daily} QOR   expires in ${hours} h`);
    console.log(`  owner tx     ${EXPLORER}${res.transactionHash}  ${c?.hybrid ? "hybrid ML-DSA-87: verified" : ""}`);
    writeDeployment({ ...d, agentRule: { perTx, daily, hours, allowedEvmCalls: [`${deskAddr}/${paySel}`], linkTx: res.transactionHash } });
  },

  async rules() {
    const o = await account("owner"), k = agentKey();
    const [r, auths, n] = await Promise.all([
      fetchSpendingRules({ rest: REST, address: o.cosmos }),
      fetchAuthenticators({ rest: REST, address: o.cosmos }),
      fetchAuthNonce({ rest: REST, address: o.cosmos, pubkey: k.pk }),
    ]);
    console.log(`account ${o.cosmos}  balance ${fmt(await balance(o.cosmos))}`);
    for (const x of r.rules) console.log(`  rule "${x.id}" ${x.enabled ? "on" : "off"}: per payment ${fmt(x.perTxLimit)}, per day ${fmt(x.dailyLimit)}, denoms ${x.allowedDenoms.join(",") || "any"}, calls ${(x.allowedEvmCalls ?? []).join(",") || "none"}`);
    const me = auths.find((a) => a.pubkeyHex.toLowerCase() === hex(k.pk));
    if (!me) { console.log("  agent key: not linked"); return; }
    console.log(`  agent key: ${me.revoked ? "REVOKED" : "linked"}, may: ${me.permissions.join(",")}, expires ${new Date(Number(me.expiryUnix) * 1000).toISOString().slice(0, 16)}Z, actions so far: ${n.nonce}`);
  },

  async inbox(series = "", due) {
    const d = readDeployment(), deskAddr = need(d, "invoiceDesk", "deploy");
    const [owner, vendorA, vendorB, attacker] = await Promise.all(["owner", "vendorA", "vendorB", "attacker"].map(account));
    const inbox = buildInbox({ desk: deskAddr, owner, vendorA, vendorB, attacker, series, due });
    const file = series ? new URL(`./inbox/inbox-${series}.json`, import.meta.url) : INBOX;
    mkdirSync(new URL("./inbox/", import.meta.url), { recursive: true });
    writeFileSync(file, JSON.stringify(inbox, null, 2) + "\n");
    console.log(`${file.pathname.split("/").slice(-2).join("/")}: ${inbox.length} emails, ${inbox.filter((m) => m.invoice).length} with ML-DSA-87 signed invoices`);
  },

  /** A new agent key for the same owner (the old one is kept, renamed). Then run "link". */
  async "new-agent"() {
    console.log(`old agent key kept as ${rotateAgentKey()}; new agent ed25519 ${hex(agentKey().pk).slice(0, 16)}...`);
  },

  async run(mode = "--compromised") {
    const { planCompromised, planLlm, execute, describe, RELAY_FEE_UQOR } = await import("./lib/agent.mjs");
    const d = readDeployment(), deskAddr = need(d, "invoiceDesk", "deploy");
    if (!existsSync(INBOX)) throw new Error('no inbox yet: run "node leash.mjs inbox" first');
    const inbox = loadInbox();
    const o = await account("owner");
    const before = await balance(o.cosmos);
    const plan = mode === "--llm" ? await planLlm(inbox) : planCompromised(inbox);
    const g = await account("gas"), gasBal = BigInt(await balance(g.cosmos));
    const needFee = RELAY_FEE_UQOR * BigInt(plan.filter((x) => x.action !== "skip").length);
    if (gasBal < needFee) throw new Error(`gas wallet has ${fmt(gasBal)}, the plan needs ${fmt(needFee)} in fees: run "node leash.mjs topup"`);
    console.log(`decider: ${mode === "--llm" ? "LLM (Claude)" : "COMPROMISED (obeys every instruction it reads)"}`);
    console.log(`owner ${o.cosmos}  balance ${fmt(before)}\n`);
    const log = [];
    for (const step of plan) {
      const m = inbox[step.item];
      if (step.action === "skip") { console.log(`- [${step.item}] ${m.subject}\n    agent: skip${step.why ? ` (${step.why})` : ""}`); log.push({ ...step, result: "skipped" }); continue; }
      const r = await execute(step, inbox, deskAddr);
      const verdict = r.ok ? `PAID${r.hybrid ? "  hybrid ML-DSA-87: verified" : ""}` : r.infra ? `NOT SENT (our side, not the chain): ${r.why}` : `REFUSED BY THE CHAIN: ${r.why}`;
      console.log(`- [${step.item}] ${m.subject}\n    agent: ${describe(step, inbox)}${step.why ? `  (${step.why})` : ""}\n    chain: ${verdict}${r.link ? `\n           ${r.link}` : ""}`);
      log.push({ ...step, ok: r.ok, infra: r.infra, why: r.why, link: r.link });
    }
    const after = await balance(o.cosmos);
    console.log(`\nowner balance ${fmt(before)} -> ${fmt(after)}  (moved ${fmt(BigInt(before) - BigInt(after))})`);
    mkdirSync(new URL("./runs/", import.meta.url), { recursive: true });
    writeFileSync(new URL(`./runs/${mode.replace(/^--/, "")}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`, import.meta.url),
      JSON.stringify({ mode, owner: o.cosmos, before, after, log }, null, 2) + "\n");
  },

  async topup(qor = "3") {
    const o = await account("owner"), g = await account("gas");
    const res = await broadcast(o, [bankSend(o.cosmos, g.cosmos, toUqor(qor))], "leash: gas top-up");
    console.log(res.code === 0 ? `gas wallet +${qor} QOR  ${EXPLORER}${res.transactionHash}` : `REFUSED code ${res.code}: ${res.rawLog}`);
  },

  async plan(mode = "--llm") {
    const { planCompromised, planLlm, describe } = await import("./lib/agent.mjs");
    const inbox = loadInbox();
    const plan = mode === "--llm" ? await planLlm(inbox) : planCompromised(inbox);
    for (const st of plan) console.log(`[${st.item}] ${inbox[st.item].subject}\n    ${describe(st, inbox)}${st.why ? `  (${st.why})` : ""}`);
    mkdirSync(new URL("./runs/", import.meta.url), { recursive: true });
    writeFileSync(new URL(`./runs/plan-${mode.replace(/^--/, "")}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`, import.meta.url), JSON.stringify(plan, null, 2) + "\n");
  },

  /**
   * A human pays an invoice the agent was not allowed to: the escalation path for anything over the
   * agent's limits. The owner signs this one directly (hybrid ML-DSA-87), so no agent rule applies,
   * but InvoiceDesk still checks the vendor, the ML-DSA-87 signature, replay and the due date.
   */
  async approve(item) {
    const deskAddr = need(readDeployment(), "invoiceDesk", "deploy");
    const inv = loadInbox()[Number(item)]?.invoice;
    if (!inv) throw new Error(`email ${item} has no invoice`);
    const o = await account("owner");
    const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID);
    const c = new Contract(deskAddr, ART.abi, new Wallet(o.privateKey, provider));
    const args = [inv.vendor, inv.amountWei, inv.id, inv.dueBy, inv.signature];
    console.log(`owner reviews ${inv.ref}: ${inv.qor} QOR to ${inv.vendor}`);
    // Dry run first: the desk's own checks, without spending anything.
    try { await c.pay.staticCall(...args, { value: inv.amountWei }); }
    catch (e) { const d = e.data ?? e.info?.error?.data; let n = e.shortMessage; try { n = c.interface.parseError(d).name; } catch { /* keep */ } throw new Error(`InvoiceDesk would refuse it: ${n}`); }
    console.log("  InvoiceDesk dry run: vendor approved, ML-DSA-87 signature valid, unpaid, not past due");
    const fees = toUqor("0.5");
    const w = await broadcast(o, [openEvmWindowMsg({ sender: o.cosmos, blocks: 300, maxTxs: 1, maxValue: String(BigInt(inv.amountWei) / 10n ** 12n + fees) })], "leash: owner approves an invoice");
    if (w.code) throw new Error(`open window REFUSED code ${w.code}: ${w.rawLog}`);
    console.log(`  EVM window: 1 tx, at most ${inv.qor} QOR + fees  ${EXPLORER}${w.transactionHash}`);
    const tx = await c.pay(...args, { value: inv.amountWei, gasLimit: 700_000 });
    const rc = await tx.wait();
    console.log(`  owner paid ${inv.ref}: ${rc.status === 1 ? "PAID" : "FAILED"}  evm tx ${tx.hash}  gas used ${rc.gasUsed}`);
    const close = await broadcast(o, [closeEvmWindowMsg(o.cosmos)], "leash: close window");
    console.log(close.code === 0 ? "  EVM window closed" : `  close window: code ${close.code}`);
    mkdirSync(new URL("./runs/", import.meta.url), { recursive: true });
    writeFileSync(new URL(`./runs/approve-${item}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`, import.meta.url),
      JSON.stringify({ item: Number(item), ref: inv.ref, qor: inv.qor, owner: o.cosmos, windowTx: w.transactionHash, evmTx: tx.hash, status: rc.status, gasUsed: String(rc.gasUsed) }, null, 2) + "\n");
  },

  async revoke() {
    const o = await account("owner"), k = agentKey();
    const res = await broadcast(o, [revokeAuthenticatorMsg({ owner: o.cosmos, scheme: "ed25519", pubkey: k.pk })], "leash: revoke agent");
    console.log(res.code === 0 ? `agent revoked  ${EXPLORER}${res.transactionHash}` : `REFUSED code ${res.code}: ${res.rawLog}`);
    if (res.code) process.exitCode = 1;
  },

  async "after-revoke"() {
    const { execute, describe } = await import("./lib/agent.mjs");
    const deskAddr = need(readDeployment(), "invoiceDesk", "deploy");
    const inbox = loadInbox();
    const step = { item: 9, action: "pay" }; // an honest, unpaid, in-limit invoice: only the revocation can stop it
    const r = await execute(step, inbox, deskAddr);
    console.log(`agent: ${describe(step, inbox)}\nchain: ${r.ok ? "PAID" : r.infra ? `NOT SENT (our side): ${r.why}` : `REFUSED BY THE CHAIN: ${r.why}`}${r.link ? `\n       ${r.link}` : ""}`);
  },
};

const [cmd, ...args] = process.argv.slice(2);
if (!cmds[cmd]) {
  console.log(readFileSync(new URL(import.meta.url), "utf8").split("\n").filter((l) => l.startsWith("//")).map((l) => l.slice(3)).join("\n"));
  process.exit(cmd ? 1 : 0);
}
cmds[cmd](...args).catch((e) => { console.error(`error: ${e?.message ?? e}`); process.exitCode = 1; });
