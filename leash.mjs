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
//   node leash.mjs fresh-owner-v2 | convert-fusd | deploy-v2 [perTx daily allowance h] | inbox-v2 | run-v2 [--compromised|--llm]
//                  approve-v2 <email> | balance-v2      v2: invoices in fUSD through InvoiceDeskV2
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
  createKeys, rotateOwnerKeys, rotateAgentKey, convertCoin, accountFromKey, fmt, hex, onChain, readDeployment, toUqor, writeDeployment,
} from "./lib/chain.mjs";
import { buildInbox, buildInboxV2, FUSD, toFusd } from "./lib/invoices.mjs";

const INBOX = process.env.LEASH_INBOX ? new URL(process.env.LEASH_INBOX, `file://${process.cwd()}/`) : new URL("./inbox/inbox.json", import.meta.url);
const ART = JSON.parse(readFileSync(new URL("./build/InvoiceDesk.json", import.meta.url), "utf8"));
const ART2 = JSON.parse(readFileSync(new URL("./build/InvoiceDeskV2.json", import.meta.url), "utf8"));
const INBOX2 = new URL("./inbox/inbox-v2.json", import.meta.url);
const ERC20 = ["function approve(address,uint256) returns (bool)", "function allowance(address,address) view returns (uint256)", "function balanceOf(address) view returns (uint256)", "function transfer(address,uint256) returns (bool)"];
const fusd = (u) => `${(Number(u) / 1e6).toLocaleString("en-US", { maximumFractionDigits: 6 })} fUSD`;
const v2 = () => need(readDeployment(), "v2", "deploy-v2");
// The agent account's rule must list (and bound) at least one denom, and the chain must be able to
// measure it, so it lists fBTC with a 1-satoshi limit: a token the agent account does not hold.
// Neither QOR nor fUSD is listed, so the agent's key cannot move either (measured on diana).
const NO_DENOM = "erc20/0x4604e7e45b2ecdbfbdc157103f5b2b62cb16451a";
const loadInbox = () => JSON.parse(readFileSync(INBOX, "utf8"));
const need = (d, k, hint) => { if (!d[k]) throw new Error(`no ${k} yet: run "node leash.mjs ${hint}" first`); return d[k]; };

// Every v2 window names its one target: whoever holds the classical key while it is open (after Q-Day,
// anyone) can reach only that contract, and only for the window's transaction count.
const scoped = (msg, targets) => { msg.value.allowedTargets = targets; return msg; };

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
      const verdict = r.ok ? `PAID${r.hybrid ? "  hybrid ML-DSA-87: verified" : ""}` : r.unknown ? `OUTCOME UNKNOWN (do not resend; check paid()): ${r.why}` : r.infra ? `NOT SENT (our side, not the chain): ${r.why}` : `REFUSED BY THE CHAIN: ${r.why}`;
      console.log(`- [${step.item}] ${m.subject}\n    agent: ${describe(step, inbox)}${step.why ? `  (${step.why})` : ""}\n    chain: ${verdict}${r.link ? `\n           ${r.link}` : ""}`);
      log.push({ ...step, ok: r.ok, infra: r.infra, unknown: r.unknown, settled: r.settled, why: r.why, link: r.link });
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

  // ------------------------------------------------------------------ v2: fUSD invoices

  /** A new owner + agent for v2, taking the previous owner's QOR (minus 0.3) and ALL its fUSD. */
  async "fresh-owner-v2"() {
    const prevName = rotateOwnerKeys();
    const prev = await accountFromKey(prevName), o = await account("owner");
    const bal = BigInt(await balance(prev.cosmos)), keep = toUqor("0.3");
    const fb = (await (await fetch(`${REST}/cosmos/bank/v1beta1/balances/${prev.cosmos}`)).json()).balances.find((b) => b.denom.toLowerCase() === `erc20:${FUSD}`.toLowerCase());
    const msgs = [bankSend(prev.cosmos, o.cosmos, bal - keep)];
    if (fb) msgs.push({ typeUrl: "/cosmos.bank.v1beta1.MsgSend", value: { fromAddress: prev.cosmos, toAddress: o.cosmos, amount: [{ denom: fb.denom, amount: fb.amount }] } });
    const res = await broadcast(prev, msgs, "leash: move to the v2 owner");
    if (res.code) throw new Error(`move REFUSED code ${res.code}: ${res.rawLog}`);
    console.log(`moved ${fmt(bal - keep)}${fb ? ` and ${fusd(fb.amount)}` : ""} from ${prev.cosmos} to the v2 owner ${o.cosmos}  ${EXPLORER}${res.transactionHash}`);
    await new Promise((r) => setTimeout(r, 6000));
    await cmds.register("owner");
  },

  /** Convert the owner's fUSD bank coin (faucet form) into its ERC-20 balance, which contracts can spend. */
  /** The company buys fUSD with QOR in the AMM (pool 2, fUSD/QOR), then converts it to its ERC-20 balance. */
  async "buy-fusd"(qor = "5", slippagePct = "3") {
    const o = await account("owner"), POOL = "2", denomOut = `erc20:${FUSD}`;
    const p = (await (await fetch(`${REST}/qorechain/amm/v1/pools/${POOL}`)).json()).pool;
    const inU = BigInt(toUqor(qor)), ra = BigInt(p.reserve_a), rb = BigInt(p.reserve_b); // a = fUSD, b = uqor
    const quote = (ra * inU) / (rb + inU), minOut = (quote * BigInt(100 - Number(slippagePct))) / 100n;
    console.log(`pool ${POOL}: ${qor} QOR -> about ${fusd(quote)} (min ${fusd(minOut)})`);
    const res = await broadcast(o, [{ typeUrl: "/qorechain.amm.v1.MsgSwapExactIn", value: { sender: o.cosmos, poolId: POOL, tokenIn: { denom: "uqor", amount: String(inU) }, denomOut, minOut: String(minOut) } }], "leash: company buys fUSD");
    if (res.code) throw new Error(`swap REFUSED code ${res.code}: ${res.rawLog}`);
    console.log(`swapped  ${EXPLORER}${res.transactionHash}`);
    await new Promise((r) => setTimeout(r, 6000));
    await cmds["convert-fusd"]();
  },

  async "convert-fusd"(amount) {
    const o = await account("owner");
    const fb = (await (await fetch(`${REST}/cosmos/bank/v1beta1/balances/${o.cosmos}`)).json()).balances.find((b) => b.denom.toLowerCase() === `erc20:${FUSD}`.toLowerCase());
    if (!fb) throw new Error("no fUSD bank coin on the owner");
    const amt = amount ? String(toFusd(amount)) : fb.amount;
    const res = await broadcast(o, [convertCoin(o.cosmos, o.evmAddr, fb.denom, amt)], "leash: fUSD coin -> ERC-20");
    console.log(res.code === 0 ? `converted ${fusd(amt)} to the ERC-20 balance of ${o.evmAddr}  ${EXPLORER}${res.transactionHash}` : `REFUSED code ${res.code}: ${res.rawLog}`);
  },

  /**
   * v2 setup, all by the owner (hybrid ML-DSA-87 txs):
   *  - the agent ACCOUNT ("agentacct"): a separate account that will hold no money. Its own key
   *    (kept by the human) registers its ML-DSA-87 key and links the agent's ed25519 key to it with a
   *    rule that allows NO denom and exactly one call, InvoiceDeskV2.pay;
   *  - InvoiceDeskV2 deployed by the owner, who approves the vendors, names the agent account,
   *    sets the fUSD limits and gives the desk an fUSD allowance (the budget).
   */
  async "deploy-v2"(perTx = "100", daily = "250", allowance = "600", hours = "72") {
    const { ensureRoleKey } = await import("./lib/chain.mjs");
    if (ensureRoleKey("agentacct")) console.log("created the agent account's key (agentacct) in the keys file");
    const o = await account("owner"), aa = await account("agentacct"), a = await account("vendorA"), b = await account("vendorB");
    // 1. the agent account: fee money, ML-DSA-87 key
    if (BigInt(await balance(aa.cosmos)) < toUqor("0.5")) {
      const f = await broadcast(o, [bankSend(o.cosmos, aa.cosmos, toUqor("1"))], "leash: fee money for the agent account");
      if (f.code) throw new Error(`fund REFUSED ${f.rawLog}`);
      console.log(`agent account ${aa.cosmos} (${aa.evmAddr}) funded with 1 QOR for its own setup fees`);
      await new Promise((r) => setTimeout(r, 6000));
    }
    await cmds.register("agentacct");
    // 2. the desk
    // a contract creation has no target to name, so the deploy gets its own one-transaction window;
    // the configuration that follows runs in a second window scoped to the new desk and the token
    const w = await broadcast(o, [openEvmWindowMsg({ sender: o.cosmos, blocks: 300, maxTxs: 1, maxValue: String(toUqor("2")) })], "leash: owner window (deploy, 1 tx)");
    if (w.code) throw new Error(`open window REFUSED code ${w.code}: ${w.rawLog}`);
    const wallet = new Wallet(o.privateKey, new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID));
    const c = await new ContractFactory(ART2.abi, ART2.bytecode, wallet).deploy();
    await c.waitForDeployment();
    const deskAddr = await c.getAddress(), txs = { window: w.transactionHash, deploy: c.deploymentTransaction().hash };
    console.log(`InvoiceDeskV2 deployed at ${deskAddr}`);
    await broadcast(o, [closeEvmWindowMsg(o.cosmos)], "leash: close the deploy window").catch(() => {}); // usually already exhausted
    const w2 = await broadcast(o, [scoped(openEvmWindowMsg({ sender: o.cosmos, blocks: 600, maxTxs: 5, maxValue: String(toUqor("3")) }), [deskAddr, FUSD])], "leash: owner window (v2 setup, desk + fUSD)");
    if (w2.code) throw new Error(`open window REFUSED code ${w2.code}: ${w2.rawLog}`);
    txs.setupWindow = w2.transactionHash;
    const step = async (label, p) => { const tx = await p; await tx.wait(); txs[label] = tx.hash; console.log(`  ${label.padEnd(18)} ${tx.hash}`); };
    await step("approve_hostline", c.approveVendor(a.evmAddr));
    await step("approve_tokenwell", c.approveVendor(b.evmAddr));
    await step("set_agent", c.setAgent(aa.evmAddr, true));
    await step("set_limit_fusd", c.setLimit(FUSD, toFusd(perTx), toFusd(daily)));
    await step("fusd_allowance", new Contract(FUSD, ERC20, wallet).approve(deskAddr, toFusd(allowance)));
    const close = await broadcast(o, [closeEvmWindowMsg(o.cosmos)], "leash: close window");
    console.log(close.code === 0 ? "EVM window closed" : `close window: code ${close.code}`);
    writeDeployment({ ...readDeployment(), v2: { invoiceDesk: deskAddr, token: FUSD, payer: o.cosmos, payerEvm: o.evmAddr, agentAccount: aa.cosmos, agentAccountEvm: aa.evmAddr,
      limits: { perTx, daily, allowance }, txs } });
    await cmds["link-v2"](hours);
  },

  /** Link the agent's key to its own account: no real denom, exactly one call (InvoiceDeskV2.pay). */
  async "link-v2"(hours = "72") {
    const d = v2(), aa = await account("agentacct"), deskAddr = d.invoiceDesk;
    const k = agentKey(), paySel = new Interface(ART2.abi).getFunction("pay").selector;
    const proof = signAuthenticatorLinkEd25519({ chainId: CHAIN_ID, account: aa.cosmos, privateKey: k.sk });
    const msgs = linkAuthenticatorMsgs({
      owner: aa.cosmos, chainId: CHAIN_ID, ...proof, permissions: ["evm"],
      expiryUnix: Math.floor(Date.now() / 1000) + Number(hours) * 3600, label: "leash invoice agent v2",
      spendingRule: { id: "leash-v2", enabled: true, perTxLimit: "0", dailyLimit: "0", allowedDenoms: [NO_DENOM], denomLimits: [{ denom: NO_DENOM, perTxLimit: "1", dailyLimit: "1" }],
        allowedEvmCalls: [`${deskAddr.toLowerCase()}/${paySel}`] },
    });
    const l = await broadcast(aa, msgs, "leash: link agent to its own account (v2)");
    if (l.code) throw new Error(`link REFUSED code ${l.code}: ${l.rawLog}`);
    
    console.log(`agent key linked to the agent account: no denom, only ${deskAddr}/${paySel}, ${hours} h  ${EXPLORER}${l.transactionHash}`);
    writeDeployment({ ...readDeployment(), v2: { ...v2(), agentRule: { allowedDenoms: [NO_DENOM], allowedEvmCalls: [`${deskAddr}/${paySel}`], hours, linkTx: l.transactionHash } } });
  },
  async "inbox-v2"(series = "", due) {
    const d = v2();
    const [owner, vendorA, vendorB, attacker] = await Promise.all(["owner", "vendorA", "vendorB", "attacker"].map(account));
    const inbox = buildInboxV2({ desk: d.invoiceDesk, owner, vendorA, vendorB, attacker, series, due });
    const file = series ? new URL(`./inbox/inbox-v2-${series}.json`, import.meta.url) : INBOX2;
    writeFileSync(file, JSON.stringify(inbox, null, 2) + "\n");
    console.log(`${file.pathname.split("/").slice(-2).join("/")}: ${inbox.length} emails, fUSD invoices signed with ML-DSA-87`);
  },

  async "run-v2"(mode = "--compromised") {
    const { planCompromisedV2, planLlm, executeV2, describeV2 } = await import("./lib/agent.mjs");
    const d = v2(), inbox = JSON.parse(readFileSync(process.env.LEASH_INBOX2 ? new URL(process.env.LEASH_INBOX2, `file://${process.cwd()}/`) : INBOX2, "utf8"));
    const o = await account("owner"), token = new Contract(FUSD, ERC20, new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID)); // the payer's money
    const before = await token.balanceOf(o.evmAddr), beforeQ = await balance(o.cosmos);
    const plan = mode === "--llm" ? await planLlm(inbox) : planCompromisedV2(inbox);
    console.log(`decider: ${mode === "--llm" ? "LLM (Claude)" : "COMPROMISED (obeys every instruction it reads)"}\nowner ${o.cosmos}  ${fusd(before)}, ${fmt(beforeQ)}\n`);
    const log = [];
    for (const step of plan) {
      const m = inbox[step.item];
      if (step.action === "skip") { console.log(`- [${step.item}] ${m.subject}\n    agent: skip${step.why ? ` (${step.why})` : ""}`); log.push({ ...step, result: "skipped" }); continue; }
      const r = await executeV2(step, inbox, d);
      const verdict = r.ok ? `PAID${r.hybrid ? "  hybrid ML-DSA-87: verified" : ""}` : r.unknown ? `OUTCOME UNKNOWN (do not resend; check paid()): ${r.why}` : r.infra ? `NOT SENT (our side): ${r.why}` : `REFUSED BY THE CHAIN: ${r.why}`;
      console.log(`- [${step.item}] ${m.subject}\n    agent: ${describeV2(step, inbox)}${step.why ? `  (${step.why})` : ""}\n    chain: ${verdict}${r.link ? `\n           ${r.link}` : ""}`);
      const { invoice, ...rest } = step;
      log.push({ ...rest, ref: (invoice ?? m.invoice)?.ref, ok: r.ok, infra: r.infra, unknown: r.unknown, settled: r.settled, why: r.why, link: r.link });
    }
    const after = await token.balanceOf(o.evmAddr), afterQ = await balance(o.cosmos);
    console.log(`\nowner ${fusd(before)} -> ${fusd(after)}  (moved ${fusd(before - after)});  QOR ${fmt(beforeQ)} -> ${fmt(afterQ)}`);
    writeFileSync(new URL(`./runs/v2-${mode.replace(/^--/, "")}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`, import.meta.url),
      JSON.stringify({ version: 2, mode, owner: o.cosmos, desk: d.invoiceDesk, fusdBefore: String(before), fusdAfter: String(after), qorBefore: beforeQ, qorAfter: afterQ, log }, null, 2) + "\n");
  },

  /** v2 human approval: the owner pays an over-limit fUSD invoice directly, after a dry run. */
  async "approve-v2"(item) {
    const d = v2(), inv = JSON.parse(readFileSync(INBOX2, "utf8"))[Number(item)]?.invoice;
    if (!inv) throw new Error(`email ${item} has no invoice`);
    const o = await account("owner"), wallet = new Wallet(o.privateKey, new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID));
    const c = new Contract(d.invoiceDesk, ART2.abi, wallet), args = [o.evmAddr, inv.token, inv.vendor, inv.amount, inv.id, inv.dueBy, inv.signature];
    console.log(`owner reviews ${inv.ref}: ${inv.fusd} fUSD to ${inv.vendor}`);
    try { await c.pay.staticCall(...args); } catch (e) { const dd = e.data ?? e.info?.error?.data; let n = e.shortMessage; try { n = c.interface.parseError(dd).name; } catch { /* keep */ } throw new Error(`InvoiceDeskV2 would refuse it: ${n}`); }
    console.log("  dry run: vendor approved, ML-DSA-87 signature valid, unpaid, not past due");
    const w = await broadcast(o, [scoped(openEvmWindowMsg({ sender: o.cosmos, blocks: 300, maxTxs: 1, maxValue: String(toUqor("0.5")) }), [d.invoiceDesk])], "leash: owner approves an fUSD invoice");
    if (w.code) throw new Error(`open window REFUSED code ${w.code}: ${w.rawLog}`);
    const tx = await c.pay(...args, { gasLimit: 700_000 }); const rc = await tx.wait();
    console.log(`  owner paid ${inv.ref}: ${rc.status === 1 ? "PAID" : "FAILED"}  evm tx ${tx.hash}`);
    const close = await broadcast(o, [closeEvmWindowMsg(o.cosmos)], "leash: close window");
    console.log(close.code === 0 ? "  EVM window closed" : `  close window: code ${close.code}`);
    writeFileSync(new URL(`./runs/v2-approve-${item}-${new Date().toISOString().replace(/[:.]/g, "-")}.json`, import.meta.url),
      JSON.stringify({ version: 2, item: Number(item), ref: inv.ref, fusd: inv.fusd, owner: o.cosmos, windowTx: w.transactionHash, evmTx: tx.hash, status: rc.status }, null, 2) + "\n");
  },

  /**
   * Treasury on the Cosmos lane, float in ERC-20. The desk pulls fUSD from the company's ERC-20 balance,
   * which an open EVM window exposes to whoever holds the classical key. So only the float stays there;
   * the rest is the bank coin, which moves only with an ML-DSA-87 signature (MsgConvertERC20 /
   * MsgConvertCoin, both hybrid-signed Cosmos messages, no window).  node leash.mjs treasury-v2 [float]
   */
  async "treasury-v2"(float = "400") {
    const { convertErc20 } = await import("./lib/chain.mjs");
    const o = await account("owner"), want = toFusd(float);
    const erc = new Contract(FUSD, ERC20, new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID));
    const have = await erc.balanceOf(o.evmAddr);
    const coin = (await (await fetch(`${REST}/cosmos/bank/v1beta1/balances/${o.cosmos}`)).json()).balances.find((x) => x.denom.toLowerCase() === `erc20:${FUSD}`.toLowerCase());
    const bank = BigInt(coin?.amount ?? 0);
    console.log(`company fUSD: ${fusd(have)} ERC-20 (float), ${fusd(bank)} bank coin (treasury); float wanted ${float}`);
    let res;
    if (have > want) res = await broadcast(o, [convertErc20(o.cosmos, o.cosmos, FUSD, have - want)], "leash: float -> treasury (ERC-20 -> bank coin)");
    else if (have < want && bank > 0n) res = await broadcast(o, [convertCoin(o.cosmos, o.evmAddr, coin.denom, (want - have < bank ? want - have : bank))], "leash: treasury -> float (bank coin -> ERC-20)");
    else return console.log("nothing to move");
    console.log(res.code === 0 ? `moved ${fusd(have > want ? have - want : want - have)}  ${EXPLORER}${res.transactionHash}` : `REFUSED code ${res.code}: ${res.rawLog}`);
  },

  /** Owner sets the desk's fUSD allowance (the budget the desk may pull, for agents and in-person payments alike). */
  async "allowance-v2"(amount) {
    const d = v2(), o = await account("owner");
    const w = await broadcast(o, [scoped(openEvmWindowMsg({ sender: o.cosmos, blocks: 300, maxTxs: 1, maxValue: String(toUqor("0.5")) }), [FUSD])], "leash: owner window (allowance)");
    if (w.code) throw new Error(`open window REFUSED code ${w.code}: ${w.rawLog}`);
    const tx = await new Contract(FUSD, ERC20, new Wallet(o.privateKey, new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID))).approve(d.invoiceDesk, toFusd(amount));
    await tx.wait();
    await broadcast(o, [closeEvmWindowMsg(o.cosmos)], "leash: close window");
    console.log(`desk allowance set to ${amount} fUSD  (evm tx ${tx.hash})`);
  },

  /**
   * The kill switch, live: one genuine, in-limit invoice. The desk would pay it for the agent; the company
   * sends setAgent(agent, false); the agent's real payment is refused (NotPayersAgent); setAgent(true);
   * the same payment goes through. Saved to runs/v2-kill-switch-<ts>.json.
   */
  async "kill-switch-v2"(fusdAmount = "20") {
    const { executeV2 } = await import("./lib/agent.mjs");
    const { signInvoiceV2 } = await import("./lib/invoices.mjs");
    const d = v2(), o = await account("owner"), aa = await account("agentacct"), b = await account("vendorB");
    const inv = signInvoiceV2(b, { desk: d.invoiceDesk, payer: o.evmAddr, vendor: b.evmAddr, fusd: fusdAmount, ref: "TOKENWELL-INV-8800-KILL", dueBy: Math.floor(Date.parse("2027-06-30T23:59:59Z") / 1000) });
    const inbox = [{ from: "accounts@tokenwell.example", subject: `Invoice ${inv.ref}: support hours`, body: "Genuine invoice, properly signed.", invoice: inv }];
    writeFileSync(new URL("./inbox/inbox-v2-KILL.json", import.meta.url), JSON.stringify(inbox, null, 2) + "\n");
    const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID), wallet = new Wallet(o.privateKey, provider);
    const c = new Contract(d.invoiceDesk, ART2.abi, wallet), args = [o.evmAddr, inv.token, inv.vendor, inv.amount, inv.id, inv.dueBy, inv.signature];
    const dry = async () => { try { await provider.call({ from: aa.evmAddr, to: d.invoiceDesk, data: c.interface.encodeFunctionData("pay", args) }); return "WOULD PAY"; } catch (e) { const dd = e.data ?? e.info?.error?.data; try { return c.interface.parseError(dd).name; } catch { return e.shortMessage; } } };
    const out = { invoice: inv.ref, fusd: fusdAmount, steps: [] };
    const note = (s) => { out.steps.push(s); console.log(`  ${s.step.padEnd(34)} ${s.result}${s.tx ? `  ${s.tx}` : ""}`); };
    console.log(`kill switch on ${inv.ref}, ${fusdAmount} fUSD, agent account ${aa.evmAddr}`);
    note({ step: "dry run as the agent", result: await dry() });
    const w = await broadcast(o, [scoped(openEvmWindowMsg({ sender: o.cosmos, blocks: 600, maxTxs: 2, maxValue: String(toUqor("0.5")) }), [d.invoiceDesk])], "leash: owner window (kill switch)");
    if (w.code) throw new Error(`open window REFUSED code ${w.code}: ${w.rawLog}`);
    let tx = await c.setAgent(aa.evmAddr, false); await tx.wait();
    note({ step: "company: setAgent(agent, false)", result: "done", tx: tx.hash });
    note({ step: "dry run as the agent", result: await dry() });
    let r = await executeV2({ item: 0, action: "pay" }, inbox, d);
    note({ step: "agent sends the payment", result: r.ok ? "PAID" : `REFUSED: ${r.why}`, tx: r.link?.slice(-64) });
    await new Promise((res) => setTimeout(res, 4000));
    tx = await c.setAgent(aa.evmAddr, true); await tx.wait();
    note({ step: "company: setAgent(agent, true)", result: "done", tx: tx.hash });
    const close = await broadcast(o, [closeEvmWindowMsg(o.cosmos)], "leash: close window");
    console.log(close.code === 0 ? "  EVM window closed" : `  close window: code ${close.code}`);
    note({ step: "dry run as the agent", result: await dry() });
    r = await executeV2({ item: 0, action: "pay" }, inbox, d);
    note({ step: "agent sends the same payment", result: r.ok ? "PAID" : `REFUSED: ${r.why}`, tx: r.link?.slice(-64) });
    writeFileSync(new URL(`./runs/v2-kill-switch-${new Date().toISOString().replace(/[:.]/g, "-")}.json`, import.meta.url), JSON.stringify(out, null, 2) + "\n");
  },

  /** Demo upkeep: a test vendor returns fUSD it was paid to the demo company (keeps the lab's in-person path funded). */
  async "vendor-refund-v2"(role = "vendorB", amount = "150") {
    const v = await account(role), o = await account("owner");
    const w = await broadcast(v, [scoped(openEvmWindowMsg({ sender: v.cosmos, blocks: 300, maxTxs: 1, maxValue: String(toUqor("0.5")) }), [FUSD])], "leash: vendor refund window");
    if (w.code) throw new Error(`open window REFUSED code ${w.code}: ${w.rawLog}`);
    const tx = await new Contract(FUSD, ERC20, new Wallet(v.privateKey, new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID))).transfer(o.evmAddr, toFusd(amount));
    await tx.wait();
    await broadcast(v, [closeEvmWindowMsg(v.cosmos)], "leash: close window");
    console.log(`${role} returned ${amount} fUSD to the company  (evm tx ${tx.hash})`);
  },

  async "balance-v2"() {
    const t = new Contract(FUSD, ERC20, new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID)), d = readDeployment().v2;
    for (const r of ROLES) { const a = await account(r); console.log(`${r.padEnd(9)} ${a.cosmos}  ${fmt(await balance(a.cosmos))}  ${fusd(await t.balanceOf(a.evmAddr))}`); }
    if (d) { const o = await account("owner"); console.log(`desk allowance ${fusd(await t.allowance(o.evmAddr, d.invoiceDesk))}`); }
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
    console.log(`agent: ${describe(step, inbox)}\nchain: ${r.ok ? "PAID" : r.unknown ? `OUTCOME UNKNOWN (do not resend): ${r.why}` : r.infra ? `NOT SENT (our side): ${r.why}` : `REFUSED BY THE CHAIN: ${r.why}`}${r.link ? `\n       ${r.link}` : ""}`);
  },
};

const [cmd, ...args] = process.argv.slice(2);
if (!cmds[cmd]) {
  console.log(readFileSync(new URL(import.meta.url), "utf8").split("\n").filter((l) => l.startsWith("//")).map((l) => l.slice(3)).join("\n"));
  process.exit(cmd ? 1 : 0);
}
cmds[cmd](...args).catch((e) => { console.error(`error: ${e?.message ?? e}`); process.exitCode = 1; });
