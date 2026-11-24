#!/usr/bin/env node
// desk.mjs: run Invoice Leash for your own company (QoreChain testnet qorechain-diana).
//
// Everything lives in $LEASH_HOME (default ~/.config/leash-desk): keys.env (mode 600) and desk.json (your
// deployment). Nothing is written to this repository. Every command is idempotent and says what to do next.
//
//   node desk.mjs init                        make the company's keys; prints the address to fund
//   node desk.mjs status                      what is set up, balances, limits, the agent, and the next step
//   node desk.mjs setup [--per-payment 100] [--daily 250] [--allowance 1000] [--float 400] [--hours 168]
//                                             register keys, fund the fee wallets, deploy your InvoiceDeskV2,
//                                             set limits, link the agent, publish its ML-KEM-1024 key
//   node desk.mjs vendor add <0x…|qor1…> <name>     approve a vendor (it must have registered its ML-DSA-87 key)
//   node desk.mjs vendor remove <0x…|qor1…>         stop paying a vendor
//   node desk.mjs vendors                     approved vendors, read from the chain
//   node desk.mjs limits <perPayment> <daily> the agent's limits, in fUSD
//   node desk.mjs agent off|on                switch the agent off (or on) in the desk: one transaction
//   node desk.mjs agent link [hours]          (re)link the agent's key; links expire
//   node desk.mjs allowance <fUSD>            how much the desk may pull from the company in total
//   node desk.mjs treasury [float]            keep only <float> fUSD in ERC-20; the rest as the bank coin
//   node desk.mjs inbox add <file.json>       add a vendor's invoice file (from vendor.mjs sign) to the inbox
//   node desk.mjs check <file.json>           verify an invoice file: ML-DSA-87 against the vendor's key on chain
//   node desk.mjs triage                      sort the inbox: AGENT PAYS / NEEDS A PERSON / REJECTED (and why)
//   node desk.mjs run                         the agent pays what triage marked AGENT PAYS, nothing else
//   node desk.mjs pay <n>                     a person pays inbox item n as the company (the approval path)
//   node desk.mjs export [file.csv]           every payment the desk made for you, from the chain, as CSV
//   node desk.mjs mcp                         an MCP config that gives an AI agent your inbox and the leash
import { homedir } from "node:os";
import { join } from "node:path";
import { existsSync, mkdirSync, readFileSync, writeFileSync, appendFileSync, chmodSync } from "node:fs";

const HOME = process.env.LEASH_HOME ?? join(homedir(), ".config", "leash-desk");
process.env.LEASH_DIR = HOME;
process.env.LEASH_DEPLOYMENT = join(HOME, "desk.json");
const INBOX = join(HOME, "inbox.json"), TRIAGE = join(HOME, "triage.json"), PAYLOG = join(HOME, "payments.jsonl");

const { Contract, ContractFactory, Interface, JsonRpcProvider, Wallet, getAddress, getBytes, formatUnits, isAddress } = await import("ethers");
const sdk = await import("@qorechain/sdk");
const chain = await import("./lib/chain.mjs");
const { CHAIN_ID, EVM_CHAIN_ID, EVM_RPC, REST, account, agentKey, balance, bankSend, broadcast, convertCoin, convertErc20, fmt, hex, readDeployment, writeDeployment, toUqor } = chain;
const { FUSD, toFusd, invoiceFacts, invoiceMessageV2, validateInvoiceV2 } = await import("./lib/invoices.mjs");

const ART2 = JSON.parse(readFileSync(new URL("./build/InvoiceDeskV2.json", import.meta.url), "utf8"));
const desk = new Interface(ART2.abi);
const ERC20 = new Interface(["function approve(address,uint256) returns (bool)", "function allowance(address,address) view returns (uint256)", "function balanceOf(address) view returns (uint256)"]);
const STATUS = new Interface(["function pqcKeyStatus(address) view returns (bool registered,uint8 algorithmId,bytes pubkey,bool possessionProven)"]);
const NO_DENOM = "erc20/0x4604e7e45b2ecdbfbdc157103f5b2b62cb16451a"; // fBTC, 1-satoshi cap: the rule must list a denom; the agent holds none
const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID, { staticNetwork: true });
const fusd = (u) => `${formatUnits(u, 6).replace(/\.0$/, "")} fUSD`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const say = (s) => console.log(s);
const fail = (s) => { throw new Error(s); };
const opt = (args, name, dflt) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : dflt; };
const view = async (to, i, fn, a) => i.decodeFunctionResult(fn, await provider.call({ to, data: i.encodeFunctionData(fn, a) }));
const D = () => readDeployment().v2 ?? {};
const save = (patch) => writeDeployment({ ...readDeployment(), v2: { ...D(), ...patch } });
const evmOf = (a) => (isAddress(a) ? getAddress(a) : getAddress(sdk.qorToEvm(a)));
const keyStatus = async (a) => { const [reg, alg, pk, proven] = await view("0x0000000000000000000000000000000000000a02", STATUS, "pqcKeyStatus", [a]); return { reg, alg: Number(alg), pk, proven }; };
// an account that has never linked a key answers 404: that is "no links", not an error
const links = (address) => sdk.fetchAuthenticators({ rest: REST, address }).catch((e) => (/404|not found/.test(e.message) ? [] : Promise.reject(e)));
const readInbox = () => (existsSync(INBOX) ? JSON.parse(readFileSync(INBOX, "utf8")) : []);

/** Ask the desk, without paying, as `from`: "OK", the desk's error name, or "network: …" after retries. */
async function dryRun(from, to, data) {
  for (let i = 0; ; i++) {
    try { await provider.call({ from, to, data }); return "OK"; }
    catch (e) {
      try { const n = desk.parseError(e.data ?? e.info?.error?.data)?.name; if (n) return n; } catch { /* not a desk error */ }
      if (i >= 3) return `network: ${e.shortMessage ?? e.message}`;
      await sleep(1500 * (i + 1));
    }
  }
}

/** A window on the company account, naming one target. Closed when `fn` is done, whatever happens. */
async function companyWindow(targets, maxTxs, fn) {
  const o = await account("owner");
  const msg = sdk.openEvmWindowMsg({ sender: o.cosmos, blocks: 300, maxTxs, maxValue: String(toUqor("0.5")) });
  if (targets) msg.value.allowedTargets = targets;
  const w = await broadcast(o, [msg], "leash desk: company window");
  if (w.code) fail(`opening the window was refused (code ${w.code}): ${w.rawLog}`);
  await sleep(3000);
  try { return await fn(new Wallet(o.privateKey, provider)); }
  finally { await broadcast(o, [sdk.closeEvmWindowMsg(o.cosmos)], "leash desk: close window").catch(() => {}); }
}
async function sendEvm(label, p) { const tx = await p; const rc = await tx.wait(); if (rc.status !== 1) fail(`${label}: reverted`); say(`  ${label.padEnd(26)} ${tx.hash}`); return tx.hash; }
async function needQor(addr, min, what) { const b = BigInt(await balance(addr)); if (b < toUqor(min)) fail(`${what} ${addr} holds ${fmt(b)}; it needs at least ${min} QOR. ${what === "the company" ? "Use the faucet (https://dashboard.qorechain.io/faucet or the QoreX wallet) for this address." : ""}`); }
async function registerPqc(role) {
  const acc = await account(role);
  if ((await sdk.fetchPqcStatus({ rest: REST, address: acc.cosmos })).registered) return false;
  const pop = sdk.signProofOfPossession({ chainId: CHAIN_ID, account: acc.cosmos, keypair: acc.pqc });
  const r = await broadcast(acc, [sdk.buildRegisterPqcKeyMsg(acc.cosmos, { pqcKeypair: acc.pqc, proofOfPossession: pop })], "leash desk: register ML-DSA-87", "classical");
  if (r.code) fail(`registering ${role}'s ML-DSA-87 key was refused: ${r.rawLog}`);
  say(`  ${role} ML-DSA-87 key registered        ${r.transactionHash}`); await sleep(5000); return true;
}

const cmds = {
  async init() {
    mkdirSync(HOME, { recursive: true, mode: 0o700 });
    const KEYS = join(HOME, "keys.env");
    if (!existsSync(KEYS)) {
      writeFileSync(KEYS, "# Invoice Leash company keys. QoreChain TESTNET only. Keep this file private.\n", { mode: 0o600 }); chmodSync(KEYS, 0o600);
    }
    for (const r of ["owner", "gas", "agentacct"]) chain.ensureRoleKey(r);
    chain.ensureHexKey("agent"); chain.ensureHexKey("agentkem");
    const o = await account("owner");
    say(`keys: ${KEYS} (mode 600). Back it up: it holds the company's keys.\n`);
    say(`company account   ${o.cosmos}  (EVM ${o.evmAddr})`);
    say(`  fund it from the faucet (https://dashboard.qorechain.io/faucet, or the QoreX wallet): about 10 QOR for fees,\n  plus the fUSD you want the desk to pay invoices with.\n`);
    say("then: node desk.mjs setup");
  },

  async status() {
    const o = await account("owner"), g = await account("gas"), aa = await account("agentacct"), d = D();
    const [ob, gb, ab] = await Promise.all([balance(o.cosmos), balance(g.cosmos), balance(aa.cosmos)]);
    const [os, as] = await Promise.all([sdk.fetchPqcStatus({ rest: REST, address: o.cosmos }), sdk.fetchPqcStatus({ rest: REST, address: aa.cosmos })]);
    say(`company       ${o.cosmos}  ${fmt(ob)}  ML-DSA-87 ${os.registered ? "registered" : "NOT registered"}`);
    say(`fee wallet    ${g.cosmos}  ${fmt(gb)}  (pays for the agent's requests)`);
    say(`agent account ${aa.cosmos}  ${fmt(ab)}  ML-DSA-87 ${as.registered ? "registered" : "NOT registered"}`);
    let next = null;
    if (!d.invoiceDesk) next = BigInt(ob) < toUqor("8") ? "fund the company account from the faucet (about 10 QOR), then: node desk.mjs setup" : "node desk.mjs setup";
    else {
      const [bal] = await view(FUSD, ERC20, "balanceOf", [o.evmAddr]), [allow] = await view(FUSD, ERC20, "allowance", [o.evmAddr, d.invoiceDesk]);
      const lim = await view(d.invoiceDesk, desk, "limits", [o.evmAddr, FUSD]), [left] = await view(d.invoiceDesk, desk, "remainingToday", [o.evmAddr, FUSD]);
      const [on] = await view(d.invoiceDesk, desk, "isAgent", [o.evmAddr, aa.evmAddr]);
      const coin = ((await chain.getJson(`/cosmos/bank/v1beta1/balances/${o.cosmos}`)).balances ?? []).find((b) => b.denom.toLowerCase() === `erc20:${FUSD}`.toLowerCase());
      const link = (await links(aa.cosmos)).find((a) => a.pubkeyHex.toLowerCase() === hex(agentKey().pk));
      const exp = link ? new Date(Number(link.expiryUnix) * 1000) : null;
      say(`desk          ${d.invoiceDesk}`);
      say(`fUSD          float ${fusd(bal)} (ERC-20, what the desk pays from), treasury ${fusd(coin?.amount ?? 0)} (bank coin); desk allowance ${fusd(allow)}`);
      say(`agent         ${on ? "ON" : "OFF"} in the desk; limits ${fusd(lim[0])} a payment, ${fusd(lim[1])} a day; ${fusd(left)} left today (UTC)`);
      say(`agent key     ${!link ? "NOT linked" : link.revoked ? "revoked" : exp < new Date() ? `EXPIRED ${exp.toISOString()}` : `linked until ${exp.toISOString()}`}`);
      say(`vendors       ${Object.keys(d.vendors ?? {}).length} approved (node desk.mjs vendors)`);
      if (!link || link.revoked || exp < new Date()) next = "node desk.mjs agent link";
      else if (BigInt(gb) < toUqor("1")) next = "the fee wallet is low: node desk.mjs setup (tops it up from the company)";
      else if (!Object.keys(d.vendors ?? {}).length) next = "approve your first vendor: node desk.mjs vendor add <address> <name> (the vendor uses vendor.mjs)";
      else if (bal === 0n) next = "no fUSD float: node desk.mjs treasury";
      else if (!on) next = "the agent is OFF: node desk.mjs agent on (or leave it off and pay in person: node desk.mjs pay <n>)";
      else {
        const t = existsSync(TRIAGE) ? JSON.parse(readFileSync(TRIAGE, "utf8")) : { items: [] }, n = readInbox().length;
        const person = t.items.filter((x) => x.verdict === "NEEDS A PERSON").map((x) => x.i);
        next = n > t.items.length ? "new invoices: node desk.mjs triage"
          : person.length ? `waiting for a person: ${person.map((i) => `node desk.mjs pay ${i}`).join(", ")} (after triage again)`
          : "add invoices: node desk.mjs inbox add <file.json>; payments so far: node desk.mjs export";
      }
    }
    say(`\nnext: ${next}`);
  },

  async setup(...args) {
    const perPayment = opt(args, "per-payment", "100"), daily = opt(args, "daily", "250"), allowance = opt(args, "allowance", "1000"), float = opt(args, "float", "400"), hours = opt(args, "hours", "168");
    const o = await account("owner"), g = await account("gas"), aa = await account("agentacct");
    say("1. the company's ML-DSA-87 key");
    await needQor(o.cosmos, "3", "the company");
    if (!(await registerPqc("owner"))) say("  already registered");
    say("2. fee money: the fee wallet (relays the agent's requests) and the agent account (its own setup)");
    for (const [acc, amt, min] of [[g, "3", "1"], [aa, "1", "0.3"]]) {
      if (BigInt(await balance(acc.cosmos)) >= toUqor(min)) { say(`  ${acc.cosmos} has enough`); continue; }
      const r = await broadcast(o, [bankSend(o.cosmos, acc.cosmos, toUqor(amt))], "leash desk: fee money");
      if (r.code) fail(`funding ${acc.cosmos} was refused: ${r.rawLog}`);
      say(`  sent ${amt} QOR to ${acc.cosmos}  ${r.transactionHash}`); await sleep(5000);
    }
    say("3. ML-DSA-87 keys for the fee wallet and the agent account");
    for (const r of ["gas", "agentacct"]) if (!(await registerPqc(r))) say(`  ${r} already registered`);
    let d = D();
    if (!d.invoiceDesk) {
      say("4. your InvoiceDeskV2 (a contract creation has no target, so it gets its own one-transaction window)");
      const { addr, block, hash } = await companyWindow(null, 1, async (w) => {
        const c = await new ContractFactory(ART2.abi, ART2.bytecode, w).deploy(); const rc = await c.deploymentTransaction().wait();
        return { addr: await c.getAddress(), block: rc.blockNumber, hash: rc.hash };
      });
      say(`  deployed                   ${hash}`);
      save({ invoiceDesk: addr, token: FUSD, payer: o.cosmos, payerEvm: o.evmAddr, agentAccount: aa.cosmos, agentAccountEvm: aa.evmAddr, gas: g.cosmos, deployedAt: new Date().toISOString(), deployBlock: block, deployTx: hash, vendors: {} });
      d = D(); say(`  InvoiceDeskV2 at ${addr}`);
    } else say(`4. desk already deployed at ${d.invoiceDesk}`);
    say("5. the desk's settings, in one window scoped to the desk and fUSD");
    const [on] = await view(d.invoiceDesk, desk, "isAgent", [o.evmAddr, aa.evmAddr]);
    const lim = await view(d.invoiceDesk, desk, "limits", [o.evmAddr, FUSD]);
    const [allow] = await view(FUSD, ERC20, "allowance", [o.evmAddr, d.invoiceDesk]);
    const todo = [!on && "agent", (lim[0] !== toFusd(perPayment) || lim[1] !== toFusd(daily)) && "limits", allow < toFusd(allowance) && "allowance"].filter(Boolean);
    if (todo.length) await companyWindow([d.invoiceDesk, FUSD], todo.length, async (w) => {
      const c = new Contract(d.invoiceDesk, ART2.abi, w);
      if (todo.includes("agent")) await sendEvm("setAgent(agent account)", c.setAgent(aa.evmAddr, true));
      if (todo.includes("limits")) await sendEvm(`setLimit(${perPayment}, ${daily})`, c.setLimit(FUSD, toFusd(perPayment), toFusd(daily)));
      if (todo.includes("allowance")) await sendEvm(`fUSD.approve(desk, ${allowance})`, new Contract(FUSD, ERC20, w).approve(d.invoiceDesk, toFusd(allowance)));
    });
    else say("  already set");
    save({ limits: { perPayment, daily, allowance } });
    say("6. the agent's key, linked to the agent account: no denom it holds, one call (InvoiceDeskV2.pay)");
    await cmds.agent("link", hours, "--quiet-if-valid");
    say("7. the agent account's ML-KEM-1024 key, so vendors can seal invoices to it");
    const { agentKemKeys, registerKemMsg, kemKeyOf } = await import("./lib/sealed.mjs");
    const kem = await kemKeyOf(aa.cosmos).catch(() => null);
    if (kem?.publicKey && Buffer.from(kem.publicKey).equals(Buffer.from(agentKemKeys().mlkemPublicKey))) say("  already registered");
    else { const r = await broadcast(aa, [registerKemMsg(aa.cosmos, agentKemKeys())], "leash desk: agent ML-KEM-1024 key"); if (r.code) fail(`KEM key refused: ${r.rawLog}`); say(`  registered                 ${r.transactionHash}`); }
    say("8. treasury and float");
    await cmds.treasury(float);
    say("\ndone. next: approve your vendors (node desk.mjs vendor add <address> <name>), then node desk.mjs status");
  },

  async vendor(sub, who, ...rest) {
    const d = D(); if (!d.invoiceDesk) fail("no desk yet: node desk.mjs setup");
    const o = await account("owner"), v = evmOf(who ?? fail("which vendor? an 0x… or qor1… address"));
    if (sub === "add") {
      const name = rest.join(" ") || fail("give the vendor a name: node desk.mjs vendor add <address> <name>");
      const k = await keyStatus(v);
      if (!k.reg || k.alg !== 1 || !k.proven) fail(`${v} has no proven ML-DSA-87 key on chain, so the desk could never pay its invoices. The vendor runs: node vendor.mjs init && node vendor.mjs register`);
      const [already] = await view(d.invoiceDesk, desk, "approved", [o.evmAddr, v]);
      if (!already) await companyWindow([d.invoiceDesk], 1, (w) => sendEvm(`approveVendor(${name})`, new Contract(d.invoiceDesk, ART2.abi, w).approveVendor(v)));
      save({ vendors: { ...(d.vendors ?? {}), [v]: name } });
      return say(`${name} (${v}) is an approved vendor; its ML-DSA-87 key: ${(k.pk.length - 2) / 2} bytes, possession proven`);
    }
    if (sub === "remove") {
      const [is] = await view(d.invoiceDesk, desk, "approved", [o.evmAddr, v]);
      if (is) await companyWindow([d.invoiceDesk], 1, (w) => sendEvm("removeVendor", new Contract(d.invoiceDesk, ART2.abi, w).removeVendor(v)));
      const vs = { ...(d.vendors ?? {}) }; delete vs[v]; save({ vendors: vs });
      return say(`${v} removed: the desk refuses its invoices from now on (UnknownVendor)`);
    }
    fail("node desk.mjs vendor add <address> <name> | vendor remove <address>");
  },

  async vendors() {
    const d = D(), o = await account("owner");
    for (const [v, name] of Object.entries(d.vendors ?? {})) {
      const [[ok], k] = await Promise.all([view(d.invoiceDesk, desk, "approved", [o.evmAddr, v]), keyStatus(v)]);
      say(`${name.padEnd(20)} ${v}  ${ok ? "approved" : "NOT approved"}  ML-DSA-87 ${k.reg && k.proven ? "registered" : "MISSING"}`);
    }
    if (!Object.keys(d.vendors ?? {}).length) say("no vendors yet: node desk.mjs vendor add <address> <name>");
  },

  async limits(perPayment, daily) {
    const d = D(); if (!perPayment || !daily) fail("node desk.mjs limits <perPayment> <daily>  (fUSD)");
    await companyWindow([d.invoiceDesk], 1, (w) => sendEvm(`setLimit(${perPayment}, ${daily})`, new Contract(d.invoiceDesk, ART2.abi, w).setLimit(FUSD, toFusd(perPayment), toFusd(daily))));
    save({ limits: { ...(D().limits ?? {}), perPayment, daily } });
  },

  async agent(sub, hours = "168", flag) {
    const d = D(), o = await account("owner"), aa = await account("agentacct");
    if (sub === "off" || sub === "on") {
      await companyWindow([d.invoiceDesk], 1, (w) => sendEvm(`setAgent(agent, ${sub === "on"})`, new Contract(d.invoiceDesk, ART2.abi, w).setAgent(aa.evmAddr, sub === "on")));
      return say(sub === "off" ? "the agent is OFF: the desk refuses its payments (NotPayersAgent) until: node desk.mjs agent on" : "the agent is ON");
    }
    if (sub !== "link") fail("node desk.mjs agent off | on | link [hours]");
    const k = agentKey();
    const cur = (await links(aa.cosmos)).find((a) => a.pubkeyHex.toLowerCase() === hex(k.pk));
    if (flag === "--quiet-if-valid" && cur && !cur.revoked && Number(cur.expiryUnix) * 1000 > Date.now() + 24 * 3600e3) return say(`  linked until ${new Date(Number(cur.expiryUnix) * 1000).toISOString()}`);
    const paySel = desk.getFunction("pay").selector;
    const proof = sdk.signAuthenticatorLinkEd25519({ chainId: CHAIN_ID, account: aa.cosmos, privateKey: k.sk });
    const msgs = sdk.linkAuthenticatorMsgs({ owner: aa.cosmos, chainId: CHAIN_ID, ...proof, permissions: ["evm"], expiryUnix: Math.floor(Date.now() / 1000) + Number(hours) * 3600, label: "leash invoice agent v2",
      spendingRule: { id: "leash-v2", enabled: true, perTxLimit: "0", dailyLimit: "0", allowedDenoms: [NO_DENOM], denomLimits: [{ denom: NO_DENOM, perTxLimit: "1", dailyLimit: "1" }], allowedEvmCalls: [`${d.invoiceDesk.toLowerCase()}/${paySel}`] } });
    const r = await broadcast(aa, msgs, "leash desk: link the agent");
    if (r.code) fail(`linking the agent was refused: ${r.rawLog}`);
    save({ agentRule: { allowedDenoms: [NO_DENOM], allowedEvmCalls: [`${d.invoiceDesk}/${paySel}`], hours, linkTx: r.transactionHash } });
    say(`  agent key linked for ${hours} h: only ${d.invoiceDesk}.pay  ${r.transactionHash}`);
  },

  async allowance(amount) {
    const d = D(); if (!amount) fail("node desk.mjs allowance <fUSD>");
    await companyWindow([FUSD], 1, (w) => sendEvm(`fUSD.approve(desk, ${amount})`, new Contract(FUSD, ERC20, w).approve(d.invoiceDesk, toFusd(amount))));
  },

  async treasury(float = "400") {
    const o = await account("owner"), want = toFusd(float);
    const [have] = await view(FUSD, ERC20, "balanceOf", [o.evmAddr]);
    const coin = ((await chain.getJson(`/cosmos/bank/v1beta1/balances/${o.cosmos}`)).balances ?? []).find((b) => b.denom.toLowerCase() === `erc20:${FUSD}`.toLowerCase());
    const bank = BigInt(coin?.amount ?? 0);
    let r;
    if (have > want) r = await broadcast(o, [convertErc20(o.cosmos, o.cosmos, FUSD, have - want)], "leash desk: float -> treasury");
    else if (have < want && bank > 0n) r = await broadcast(o, [convertCoin(o.cosmos, o.evmAddr, coin.denom, want - have < bank ? want - have : bank)], "leash desk: treasury -> float");
    if (r?.code) fail(`moving fUSD was refused: ${r.rawLog}`);
    if (r) await sleep(5000);
    const [now] = await view(FUSD, ERC20, "balanceOf", [o.evmAddr]);
    const coin2 = ((await chain.getJson(`/cosmos/bank/v1beta1/balances/${o.cosmos}`)).balances ?? []).find((b) => b.denom.toLowerCase() === `erc20:${FUSD}`.toLowerCase());
    say(`  float ${fusd(now)} (ERC-20, the desk pays from it), treasury ${fusd(coin2?.amount ?? 0)} (bank coin, moves only with ML-DSA-87)${r ? `  ${r.transactionHash}` : ""}`);
    if (now < want) say(`  the float is below ${float} fUSD: get fUSD from the faucet, then run this again`);
  },

  async inbox(sub, file) {
    if (sub !== "add" || !file) fail("node desk.mjs inbox add <file.json>");
    const items = [JSON.parse(readFileSync(file, "utf8"))].flat();
    for (const m of items) if (!m.sealed) validateInvoiceV2(m.invoice ?? fail(`${file}: no invoice and nothing sealed`));
    const all = readInbox(); all.push(...items); writeFileSync(INBOX, JSON.stringify(all, null, 2) + "\n");
    say(`${items.length} added; the inbox has ${all.length}. next: node desk.mjs triage`);
  },

  async check(file) {
    const m = JSON.parse(readFileSync(file ?? fail("node desk.mjs check <file.json>"), "utf8"));
    const v = m.invoice ?? (m.sealed ? (await import("./lib/sealed.mjs")).openInvoice(m.sealed) : fail("no invoice in the file"));
    validateInvoiceV2(v);
    const d = D(), k = await keyStatus(v.vendor), f = invoiceFacts(v);
    const msg = invoiceMessageV2({ desk: d.invoiceDesk, payer: d.payerEvm, vendor: v.vendor, token: v.token, amount: BigInt(v.amount), id: v.id, dueBy: v.dueBy });
    const sigOk = k.reg && sdk.pqcVerify(getBytes(k.pk), msg, getBytes(v.signature));
    say(`${JSON.stringify(v.ref)}: ${f.amount} to ${d.vendors?.[getAddress(v.vendor)] ?? "an unknown vendor"} (${v.vendor}), due ${new Date(v.dueBy * 1000).toISOString().slice(0, 10)}`);
    for (const w of f.warnings) say(`WARNING: ${w}`);
    say(sigOk ? "ML-DSA-87 signature: VALID under the vendor's registered key, for your desk and your company" : `ML-DSA-87 signature: NOT VALID ${k.reg ? "under the vendor's registered key (forged, edited, or for another desk or payer)" : "(the vendor has no registered key)"}`);
  },

  async triage() {
    const d = D(), o = await account("owner"), aa = await account("agentacct"), items = readInbox();
    const { openInvoice } = await import("./lib/sealed.mjs");
    const out = [];
    for (const [i, m] of items.entries()) {
      let v = m.invoice, note = "";
      if (!v && m.sealed) { try { v = validateInvoiceV2(openInvoice(m.sealed)); note = "sealed (opened with the agent's ML-KEM-1024 key)"; } catch (e) { out.push({ i, verdict: "REJECTED", why: `sealed, cannot open: ${e.message}` }); continue; } }
      if (!v) { out.push({ i, verdict: "REJECTED", why: "no invoice" }); continue; }
      const f = invoiceFacts(v), data = desk.encodeFunctionData("pay", [o.evmAddr, v.token, v.vendor, v.amount, v.id, v.dueBy, v.signature]);
      const ask = (from) => dryRun(from, d.invoiceDesk, data);
      const [asAgent, asCompany] = [await ask(aa.evmAddr), await ask(o.evmAddr)];
      let verdict, why;
      if (asAgent === "OK" && !f.warnings.length) { verdict = "AGENT PAYS"; why = "approved vendor, valid ML-DSA-87 signature, unpaid, not past due, within the agent's limits"; }
      else if (asAgent === "OK") { verdict = "NEEDS A PERSON"; why = `valid, but: ${f.warnings.join("; ")}`; }
      else if (asCompany === "OK") {
        verdict = "NEEDS A PERSON";
        const because = { OverPerPaymentLimit: "over the agent's per-payment limit", OverDailyLimit: "over what the agent may still pay today (UTC)", NotPayersAgent: "the agent is switched off (node desk.mjs agent on)" }[asAgent] ?? asAgent;
        why = `valid, but the agent may not pay it: ${because}. A person can: node desk.mjs pay ${i}`;
      }
      else if (asCompany === "AlreadyPaid") { verdict = "ALREADY PAID"; why = "the desk has paid this invoice id for you (node desk.mjs export)"; }
      else if (/^network/.test(asCompany)) { verdict = "TRY AGAIN"; why = asCompany; }
      else { verdict = "REJECTED"; why = asCompany; }
      out.push({ i, ref: v.ref, id: v.id, vendor: v.vendor, vendorName: d.vendors?.[getAddress(v.vendor)] ?? null, amount: f.amount, verdict, why, note });
    }
    writeFileSync(TRIAGE, JSON.stringify({ at: new Date().toISOString(), items: out }, null, 2) + "\n");
    for (const x of out) say(`${String(x.i).padStart(3)}  ${x.verdict.padEnd(15)} ${(x.ref ?? "").slice(0, 34).padEnd(34)} ${(x.amount ?? "").padEnd(12)} ${x.vendorName ?? ""}\n       ${x.why}${x.note ? ` · ${x.note}` : ""}`);
    say(`\nsaved to ${TRIAGE}. next: node desk.mjs run (pays only AGENT PAYS)`);
  },

  async run() {
    if (!existsSync(TRIAGE)) fail("triage first: node desk.mjs triage");
    const { executeV2 } = await import("./lib/agent.mjs");
    const t = JSON.parse(readFileSync(TRIAGE, "utf8")), items = readInbox(), d = D();
    if (Date.now() - Date.parse(t.at) > 3600e3) fail("the triage is over an hour old: run node desk.mjs triage again");
    const { openInvoice } = await import("./lib/sealed.mjs");
    for (const x of t.items.filter((x) => x.verdict === "AGENT PAYS")) {
      const m = items[x.i], inv = m.invoice ?? openInvoice(m.sealed);
      if (inv.id !== x.id) fail(`inbox item ${x.i} changed since triage`);
      const r = await executeV2({ item: x.i, action: "pay", invoice: inv }, items, d);
      const line = { at: new Date().toISOString(), by: "agent", i: x.i, ref: inv.ref, id: inv.id, vendor: inv.vendor, amount: inv.amount, token: inv.token, ok: r.ok, unknown: r.unknown, why: r.why, link: r.link };
      appendFileSync(PAYLOG, JSON.stringify(line) + "\n");
      say(`${r.ok ? "PAID          " : r.unknown ? "UNKNOWN       " : r.infra ? "NOT SENT      " : "REFUSED       "} ${inv.ref}  ${x.amount}  ${r.ok ? r.link : r.why}`);
    }
  },

  async pay(n) {
    const d = D(), o = await account("owner"), m = readInbox()[Number(n)] ?? fail(`no inbox item ${n}`);
    const inv = m.invoice ?? (await import("./lib/sealed.mjs")).openInvoice(m.sealed);
    validateInvoiceV2(inv);
    const c = new Contract(d.invoiceDesk, ART2.abi, provider), args = [o.evmAddr, inv.token, inv.vendor, inv.amount, inv.id, inv.dueBy, inv.signature];
    const verdict = await dryRun(o.evmAddr, d.invoiceDesk, desk.encodeFunctionData("pay", args));
    if (verdict !== "OK") fail(/^network/.test(verdict) ? `could not ask the desk (${verdict}); try again` : `the desk would refuse it: ${verdict}`);
    say(`paying ${inv.ref}, ${invoiceFacts(inv).amount} to ${d.vendors?.[getAddress(inv.vendor)] ?? inv.vendor}, as the company`);
    const h = await companyWindow([d.invoiceDesk], 1, (w) => sendEvm("pay (as the company)", c.connect(w).pay(...args, { gasLimit: 700_000 })));
    appendFileSync(PAYLOG, JSON.stringify({ at: new Date().toISOString(), by: "company", i: Number(n), ref: inv.ref, id: inv.id, vendor: inv.vendor, amount: inv.amount, token: inv.token, ok: true, link: h }) + "\n");
  },

  async export(file) {
    const d = D(); if (!d.invoiceDesk) fail("no desk yet");
    const known = new Map();
    for (const m of readInbox()) { let v = m.invoice; if (!v && m.sealed) try { v = (await import("./lib/sealed.mjs")).openInvoice(m.sealed); } catch { /* skip */ } if (v) known.set(v.id, v.ref); }
    const rows = new Map(); // invoice id -> row: a desk pays an id at most once
    const row = (at, vendor, id, token, amount, by, tx) => {
      vendor = getAddress(vendor); token = getAddress(token);
      const fu = token === getAddress(FUSD);
      rows.set(id, [at, d.vendors?.[vendor] ?? "", vendor, known.get(id) ?? "", id, formatUnits(amount, fu ? 6 : 18), fu ? "fUSD" : "QOR", by, tx]);
    };
    // 1. payments the company sent itself: ordinary EVM transactions, so InvoicePaid is in eth_getLogs
    const topic = desk.getEvent("InvoicePaid").topicHash, payerTopic = "0x" + d.payerEvm.slice(2).toLowerCase().padStart(64, "0");
    const head = await provider.getBlockNumber();
    for (let b = d.deployBlock ?? head - 200_000; b <= head; b += 10_000) {
      for (const l of await provider.getLogs({ address: d.invoiceDesk, topics: [topic, payerTopic], fromBlock: b, toBlock: Math.min(b + 9_999, head) })) {
        const e = desk.parseLog(l), blk = await provider.getBlock(l.blockNumber);
        const by = getAddress(e.args.by) === getAddress(d.agentAccountEvm) ? "agent" : getAddress(e.args.by) === getAddress(d.payerEvm) ? "company" : e.args.by;
        row(new Date(blk.timestamp * 1000).toISOString(), e.args.vendor, e.args.id, e.args.token, e.args.amount, by, l.transactionHash);
      }
    }
    // 2. payments the agent sent: relayed MsgExecuteEVM (authenticator lane). Measured on diana: these emit
    //    no log that eth_getLogs returns, so they are read from the relayer's Cosmos transactions, decoded,
    //    and confirmed with the desk's own paid() record.
    const paySel = desk.getFunction("pay").selector;
    const q = encodeURIComponent(`message.sender='${d.gas}'`);
    for (let page = 1; ; page++) {
      const r = await chain.getJson(`/cosmos/tx/v1beta1/txs?query=${q}&pagination.limit=100&page=${page}&order_by=ORDER_BY_ASC`);
      const txs = r.tx_responses ?? [];
      for (const t of txs) {
        if (t.code !== 0 || t.events.some((e) => e.type === "abstractaccount_execution_failed")) continue;
        for (const m of t.tx.body.messages) {
          if (m["@type"] !== "/qorechain.abstractaccount.v1.MsgExecuteEVM" || m.account !== d.agentAccount || getAddress(m.to) !== getAddress(d.invoiceDesk)) continue;
          const data = "0x" + Buffer.from(m.data, "base64").toString("hex");
          if (!data.startsWith(paySel)) continue;
          const [payer, token, vendor, amount, id] = desk.decodeFunctionData("pay", data);
          if (getAddress(payer) !== getAddress(d.payerEvm) || rows.has(id)) continue;
          const [isPaid] = await view(d.invoiceDesk, desk, "paid", [d.payerEvm, id]);
          if (isPaid) row(new Date(t.timestamp).toISOString(), vendor, id, token, amount, "agent", t.txhash);
        }
      }
      if (txs.length < 100) break;
    }
    const sorted = [...rows.values()].sort((a, b) => a[0].localeCompare(b[0]));
    const qcsv = (x) => (/[",\n]/.test(String(x)) ? `"${String(x).replace(/"/g, '""')}"` : String(x));
    const csv = [["paid_at_utc", "vendor_name", "vendor", "invoice_ref", "invoice_id", "amount", "currency", "paid_by", "tx"], ...sorted].map((r) => r.map(qcsv).join(",")).join("\n") + "\n";
    if (file) { writeFileSync(file, csv); say(`${sorted.length} payments written to ${file}`); } else process.stdout.write(csv);
    const unknownRef = sorted.filter((r) => !r[3]).length;
    if (unknownRef) console.error(`${unknownRef} payment(s) with no invoice in your inbox: check them`);
  },

  async mcp() {
    say(JSON.stringify({ mcpServers: { "invoice-leash": { command: "node", args: [new URL("./mcp/server.mjs", import.meta.url).pathname], env: { LEASH_DIR: HOME, LEASH_DEPLOYMENT: join(HOME, "desk.json"), LEASH_INBOX2: INBOX } } } }, null, 2));
    console.error("\nsave as .mcp.json (or pass with claude --mcp-config). The server holds only the agent's key; the desk and the chain hold the limits.");
  },
};

const [cmd, ...args] = process.argv.slice(2);
if (!cmds[cmd]) { say(readFileSync(new URL(import.meta.url), "utf8").split("\n").filter((l) => l.startsWith("//")).slice(0, 26).map((l) => l.slice(3)).join("\n")); process.exit(cmd ? 1 : 0); }
try { await cmds[cmd](...args); } catch (e) { console.error(`\n${e.message || e.shortMessage || e.code || e}`); if (process.env.LEASH_DEBUG) console.error(e); process.exitCode = 1; }
