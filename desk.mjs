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
//   node desk.mjs freeze                      stop everything now: agent off, its key revoked on chain, windows closed
//   node desk.mjs unfreeze [hours]            the agent on again, its key relinked
//   node desk.mjs agent link [hours]          (re)link the agent's key; links expire
//   node desk.mjs allowance <fUSD>            how much the desk may pull from the company in total
//   node desk.mjs treasury [float]            keep only <float> fUSD in ERC-20; the rest as the bank coin
//   node desk.mjs inbox add <file.json>       add a vendor's invoice file (from vendor.mjs sign) to the inbox
//   node desk.mjs inbox archive               set the inbox aside (after an upgrade, old invoices name the old desk)
//   node desk.mjs upgrade [--keep-old]        move a company to InvoiceDeskV4 (from V2 or V3), settings and agent included
//   node desk.mjs check <file.json>           verify an invoice file: ML-DSA-87 against the vendor's key on chain
//   node desk.mjs triage                      sort the inbox: AGENT PAYS / NEEDS A PERSON / REJECTED (and why)
//   node desk.mjs run                         the agent pays what triage marked AGENT PAYS, nothing else
//   node desk.mjs pay <n>                     a person pays inbox item n as the company (the approval path)
//   node desk.mjs export [file.csv]           every payment the desk made for you, from the chain, as CSV
//   node desk.mjs mcp                         an MCP config that gives an AI agent your inbox and the leash
//   node desk.mjs serve [port]                the Desk Console's local signer (docs/app.html): your keys stay here
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
const ART3 = JSON.parse(readFileSync(new URL("./build/InvoiceDeskV3.json", import.meta.url), "utf8"));
const ART4 = JSON.parse(readFileSync(new URL("./build/InvoiceDeskV4.json", import.meta.url), "utf8"));
const ARTS = { 2: ART2, 3: ART3, 4: ART4 };
// New desks are InvoiceDeskV3. A company set up before V3 keeps its V2 desk until `upgrade`.
// New desks are InvoiceDeskV4 (V3 + the agent's own ML-DSA-87 signature). Older ones keep their version until `upgrade`.
const art = (d = D()) => ARTS[d.version ?? 2];
const desk = new Interface(ART4.abi); // V4's ABI parses every V2/V3 error too; pay() and paid() differ by version (lib/agent.mjs)
const ERC20 = new Interface(["function approve(address,uint256) returns (bool)", "function allowance(address,address) view returns (uint256)", "function balanceOf(address) view returns (uint256)"]);
const STATUS = new Interface(["function pqcKeyStatus(address) view returns (bool registered,uint8 algorithmId,bytes pubkey,bool possessionProven)"]);
const NO_DENOM = "erc20/0x4604e7e45b2ecdbfbdc157103f5b2b62cb16451a"; // fBTC, 1-satoshi cap: the rule must list a denom; the agent holds none
const provider = new JsonRpcProvider(EVM_RPC, EVM_CHAIN_ID, { staticNetwork: true });
const fusd = (u) => `${formatUnits(u, 6).replace(/\.0$/, "")} fUSD`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// output goes to the terminal, or, while `serve` handles a request, to that request's log
let sink = null;
const say = (s) => (sink ? sink.push(String(s)) : console.log(s));
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
    for (const r of ["owner", "gas", "agentacct", "agentsigner"]) chain.ensureRoleKey(r);
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
    chain.ensureRoleKey("agentsigner");
    const sg = await account("agentsigner");
    for (const [acc, amt, min] of [[g, "3", "1"], [aa, "1", "0.3"], [sg, "0.3", "0.05"]]) {
      if (BigInt(await balance(acc.cosmos)) >= toUqor(min)) { say(`  ${acc.cosmos} has enough`); continue; }
      const r = await broadcast(o, [bankSend(o.cosmos, acc.cosmos, toUqor(amt))], "leash desk: fee money");
      if (r.code) fail(`funding ${acc.cosmos} was refused: ${r.rawLog}`);
      say(`  sent ${amt} QOR to ${acc.cosmos}  ${r.transactionHash}`); await sleep(5000);
    }
    say("3. ML-DSA-87 keys for the fee wallet and the agent account");
    for (const r of ["gas", "agentacct", "agentsigner"]) if (!(await registerPqc(r))) say(`  ${r} already registered`);
    let d = D();
    if (!d.invoiceDesk) {
      say("4. your InvoiceDeskV4 (a contract creation has no target, so it gets its own one-transaction window)");
      const { addr, block, hash } = await companyWindow(null, 1, async (w) => {
        const c = await new ContractFactory(ART4.abi, ART4.bytecode, w).deploy(); const rc = await c.deploymentTransaction().wait();
        return { addr: await c.getAddress(), block: rc.blockNumber, hash: rc.hash };
      });
      say(`  deployed                   ${hash}`);
      save({ version: 4, invoiceDesk: addr, token: FUSD, payer: o.cosmos, payerEvm: o.evmAddr, agentAccount: aa.cosmos, agentAccountEvm: aa.evmAddr, gas: g.cosmos, deployedAt: new Date().toISOString(), deployBlock: block, deployTx: hash, vendors: {} });
      d = D(); say(`  InvoiceDeskV4 at ${addr}`);
    } else say(`4. desk already deployed at ${d.invoiceDesk} (InvoiceDeskV${d.version ?? 2})`);
    say("5. the desk's settings, in one window scoped to the desk and fUSD");
    const [on] = await view(d.invoiceDesk, desk, "isAgent", [o.evmAddr, aa.evmAddr]);
    const lim = await view(d.invoiceDesk, desk, "limits", [o.evmAddr, FUSD]);
    const [allow] = await view(FUSD, ERC20, "allowance", [o.evmAddr, d.invoiceDesk]);
    const signerSet = d.version === 4 ? (await view(d.invoiceDesk, desk, "agentSigner", [o.evmAddr, aa.evmAddr]))[0] : null;
    const todo = [!on && "agent", d.version === 4 && getAddress(signerSet) !== getAddress(sg.evmAddr) && "signer", (lim[0] !== toFusd(perPayment) || lim[1] !== toFusd(daily)) && "limits", allow < toFusd(allowance) && "allowance"].filter(Boolean);
    if (todo.length) await companyWindow([d.invoiceDesk, FUSD], todo.length, async (w) => {
      const c = new Contract(d.invoiceDesk, art().abi, w);
      if (todo.includes("agent")) await sendEvm("setAgent(agent account)", c.setAgent(aa.evmAddr, true));
      if (todo.includes("signer")) await sendEvm("setAgentSigner(ML-DSA-87)", c.setAgentSigner(aa.evmAddr, sg.evmAddr));
      if (todo.includes("limits")) await sendEvm(`setLimit(${perPayment}, ${daily})`, c.setLimit(FUSD, toFusd(perPayment), toFusd(daily)));
      if (todo.includes("allowance")) await sendEvm(`fUSD.approve(desk, ${allowance})`, new Contract(FUSD, ERC20, w).approve(d.invoiceDesk, toFusd(allowance)));
    });
    else say("  already set");
    save({ limits: { perPayment, daily, allowance } });
    say("6. the agent's key, linked to the agent account: no denom it holds, one call (the desk's pay)");
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
      if (!already) await companyWindow([d.invoiceDesk], 1, (w) => sendEvm(`approveVendor(${name})`, new Contract(d.invoiceDesk, art().abi, w).approveVendor(v)));
      save({ vendors: { ...(d.vendors ?? {}), [v]: name } });
      return say(`${name} (${v}) is an approved vendor; its ML-DSA-87 key: ${(k.pk.length - 2) / 2} bytes, possession proven`);
    }
    if (sub === "remove") {
      const [is] = await view(d.invoiceDesk, desk, "approved", [o.evmAddr, v]);
      if (is) await companyWindow([d.invoiceDesk], 1, (w) => sendEvm("removeVendor", new Contract(d.invoiceDesk, art().abi, w).removeVendor(v)));
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
    await companyWindow([d.invoiceDesk], 1, (w) => sendEvm(`setLimit(${perPayment}, ${daily})`, new Contract(d.invoiceDesk, art().abi, w).setLimit(FUSD, toFusd(perPayment), toFusd(daily))));
    save({ limits: { ...(D().limits ?? {}), perPayment, daily } });
  },

  async agent(sub, hours = "168", flag) {
    const d = D(), o = await account("owner"), aa = await account("agentacct");
    if (sub === "off" || sub === "on") {
      await companyWindow([d.invoiceDesk], 1, (w) => sendEvm(`setAgent(agent, ${sub === "on"})`, new Contract(d.invoiceDesk, art().abi, w).setAgent(aa.evmAddr, sub === "on")));
      return say(sub === "off" ? "the agent is OFF: the desk refuses its payments (NotPayersAgent) until: node desk.mjs agent on" : "the agent is ON");
    }
    if (sub !== "link") fail("node desk.mjs agent off | on | link [hours]");
    const k = agentKey();
    const cur = (await links(aa.cosmos)).find((a) => a.pubkeyHex.toLowerCase() === hex(k.pk));
    if (flag === "--quiet-if-valid" && cur && !cur.revoked && Number(cur.expiryUnix) * 1000 > Date.now() + 24 * 3600e3) return say(`  linked until ${new Date(Number(cur.expiryUnix) * 1000).toISOString()}`);
    const paySel = new Interface(art(d).abi).getFunction("pay").selector; // V4's pay takes the agent's signature too
    const proof = sdk.signAuthenticatorLinkEd25519({ chainId: CHAIN_ID, account: aa.cosmos, privateKey: k.sk });
    const msgs = sdk.linkAuthenticatorMsgs({ owner: aa.cosmos, chainId: CHAIN_ID, ...proof, permissions: ["evm"], expiryUnix: Math.floor(Date.now() / 1000) + Number(hours) * 3600, label: "leash invoice agent v2",
      spendingRule: { id: "leash-v2", enabled: true, perTxLimit: "0", dailyLimit: "0", allowedDenoms: [NO_DENOM], denomLimits: [{ denom: NO_DENOM, perTxLimit: "1", dailyLimit: "1" }], allowedEvmCalls: [`${d.invoiceDesk.toLowerCase()}/${paySel}`] } });
    const r = await broadcast(aa, msgs, "leash desk: link the agent");
    if (r.code) fail(`linking the agent was refused: ${r.rawLog}`);
    save({ agentRule: { allowedDenoms: [NO_DENOM], allowedEvmCalls: [`${d.invoiceDesk}/${paySel}`], hours, linkTx: r.transactionHash } });
    say(`  agent key linked for ${hours} h: only ${d.invoiceDesk}.pay  ${r.transactionHash}`);
  },

  /**
   * Stop everything, now: the agent off in the desk, its key revoked on chain, any open window closed.
   * Each step is independent, so one failing does not stop the others. Undo with `node desk.mjs unfreeze`.
   */
  async freeze() {
    const d = D(), o = await account("owner"), aa = await account("agentacct"), k = agentKey(), done = [];
    const step = async (label, fn) => { try { await fn(); done.push(`OK    ${label}`); } catch (e) { done.push(`FAIL  ${label}: ${e.message}`); } };
    await step("the agent off in the desk (setAgent false)", () => companyWindow([d.invoiceDesk], 1, (w) => sendEvm("setAgent(agent, false)", new Contract(d.invoiceDesk, art().abi, w).setAgent(aa.evmAddr, false))));
    await step("the agent's key revoked on chain", async () => {
      const cur = (await links(aa.cosmos)).find((a) => a.pubkeyHex.toLowerCase() === hex(k.pk));
      if (!cur || cur.revoked) return say("  the agent's key was not linked");
      const r = await broadcast(aa, [sdk.revokeAuthenticatorMsg({ owner: aa.cosmos, scheme: "ed25519", pubkey: k.pk })], "leash desk: freeze, revoke the agent's key");
      if (r.code) fail(`refused: ${r.rawLog}`);
      say(`  revoked                    ${r.transactionHash}`);
    });
    for (const [who, acc] of [["company", o], ["agent account", aa]]) await step(`any open EVM window on the ${who} closed`, async () => {
      const w = await sdk.fetchEvmWindow({ rest: REST, address: acc.cosmos }).catch(() => null);
      if (!w?.live) return;
      const r = await broadcast(acc, [sdk.closeEvmWindowMsg(acc.cosmos)], "leash desk: freeze, close window");
      if (r.code) fail(`refused: ${r.rawLog}`);
    });
    say(`\nFROZEN:\n  ${done.join("\n  ")}\nthe agent can pay nothing now. To resume: node desk.mjs unfreeze`);
    if (done.some((x) => x.startsWith("FAIL"))) process.exitCode = 1;
  },

  async unfreeze(hours = "168") {
    await cmds.agent("on");
    await cmds.agent("link", hours);
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
    if (sub === "archive") {
      // e.g. after an upgrade: invoices signed for the old desk do not verify on the new one
      const stamp = new Date().toISOString().replace(/[:.]/g, "-");
      for (const f of [INBOX, TRIAGE]) if (existsSync(f)) writeFileSync(f.replace(/\.json$/, `-${stamp}.json`), readFileSync(f)), writeFileSync(f, f === INBOX ? "[]\n" : JSON.stringify({ at: new Date(0).toISOString(), items: [] }) + "\n");
      return say(`inbox archived (${stamp}); it is empty now`);
    }
    if (sub !== "add" || !file) fail("node desk.mjs inbox add <file.json> | inbox archive");
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
      const { payData } = await import("./lib/agent.mjs");
      const f = invoiceFacts(v);
      const [asAgent, asCompany] = [await dryRun(aa.evmAddr, d.invoiceDesk, await payData(d, v, { asAgent: true })), await dryRun(o.evmAddr, d.invoiceDesk, await payData(d, v, { asAgent: false }))];
      let verdict, why;
      if (asAgent === "OK" && !f.warnings.length) { verdict = "AGENT PAYS"; why = "approved vendor, valid ML-DSA-87 signature, unpaid, not past due, within the agent's limits"; }
      else if (asAgent === "OK") { verdict = "NEEDS A PERSON"; why = `valid, but: ${f.warnings.join("; ")}`; }
      else if (asCompany === "OK") {
        verdict = "NEEDS A PERSON";
        const because = { OverPerPaymentLimit: "over the agent's per-payment limit", OverDailyLimit: "over what the agent may still pay today (UTC)", NotPayersAgent: "the agent is switched off (node desk.mjs agent on)", PastDue: "it is past due; an agent may not pay late, the company may settle it" }[asAgent] ?? asAgent;
        why = `valid, but the agent may not pay it: ${because}. A person can: node desk.mjs pay ${i}`;
      }
      else if (asAgent === "TransferFailed" || asCompany === "TransferFailed") { verdict = "NEEDS FUNDS"; why = "valid, but the transfer would fail: the company's fUSD float or the desk's allowance is too low (node desk.mjs status; node desk.mjs treasury <float> or allowance <fUSD>)"; }
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
    const c = new Contract(d.invoiceDesk, art().abi, provider), args = [o.evmAddr, inv.token, inv.vendor, inv.amount, inv.id, inv.dueBy, inv.signature, ...(d.version === 4 ? ["0x"] : [])];
    const { payData } = await import("./lib/agent.mjs");
    const verdict = await dryRun(o.evmAddr, d.invoiceDesk, await payData(d, inv, { asAgent: false }));
    if (verdict !== "OK") fail(/^network/.test(verdict) ? `could not ask the desk (${verdict}); try again` : `the desk would refuse it: ${verdict}`);
    say(`paying ${inv.ref}, ${invoiceFacts(inv).amount} to ${d.vendors?.[getAddress(inv.vendor)] ?? inv.vendor}, as the company`);
    const h = await companyWindow([d.invoiceDesk], 1, (w) => sendEvm("pay (as the company)", c.connect(w).pay(...args, { gasLimit: 700_000 })));
    appendFileSync(PAYLOG, JSON.stringify({ at: new Date().toISOString(), by: "company", i: Number(n), ref: inv.ref, id: inv.id, vendor: inv.vendor, amount: inv.amount, token: inv.token, ok: true, link: h }) + "\n");
  },

  async export(file) {
    const cur = D(); if (!cur.invoiceDesk) fail("no desk yet");
    // every desk this company has used: the current one and any it upgraded from
    const desks = [...(cur.previous ?? []).map((p) => ({ ...cur, ...p })), cur];
    const known = new Map();
    // invoice references: from the inbox and every archived inbox
    const { readdirSync } = await import("node:fs");
    const inboxes = [INBOX, ...readdirSync(HOME).filter((f) => /^inbox-.*\.json$/.test(f)).map((f) => join(HOME, f))].filter(existsSync);
    for (const f of inboxes) for (const m of JSON.parse(readFileSync(f, "utf8"))) { let v = m.invoice; if (!v && m.sealed) try { v = (await import("./lib/sealed.mjs")).openInvoice(m.sealed); } catch { /* skip */ } if (v) known.set(v.id, v.ref); }
    const rows = new Map(); // (desk, vendor, invoice id) -> row: a desk pays each at most once
    let this_desk;
    const row = (at, vendor, id, token, amount, by, tx) => {
      vendor = getAddress(vendor); token = getAddress(token);
      const fu = token === getAddress(FUSD);
      rows.set(`${this_desk}|${vendor}|${id}`, [at, cur.vendors?.[vendor] ?? "", vendor, known.get(id) ?? "", id, formatUnits(amount, fu ? 6 : 18), fu ? "fUSD" : "QOR", by, tx, this_desk]);
    };
    for (const d of desks) {
      this_desk = getAddress(d.invoiceDesk);
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
      const { deskOf } = await import("./lib/agent.mjs");
      const di = deskOf(d), paySel = di.getFunction("pay").selector;
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
            const [payer, token, vendor, amount, id] = di.decodeFunctionData("pay", data);
            if (getAddress(payer) !== getAddress(d.payerEvm) || rows.has(`${this_desk}|${getAddress(vendor)}|${id}`)) continue;
            const { paidArgs } = await import("./lib/agent.mjs");
            const { deskOf } = await import("./lib/agent.mjs");
            const [isPaid] = await view(d.invoiceDesk, deskOf(d), "paid", paidArgs(d, vendor, id));
            if (isPaid) row(new Date(t.timestamp).toISOString(), vendor, id, token, amount, "agent", t.txhash);
          }
        }
        if (txs.length < 100) break;
      }
    }
    const sorted = [...rows.values()].sort((a, b) => a[0].localeCompare(b[0]));
    const qcsv = (x) => (/[",\n]/.test(String(x)) ? `"${String(x).replace(/"/g, '""')}"` : String(x));
    const csv = [["paid_at_utc", "vendor_name", "vendor", "invoice_ref", "invoice_id", "amount", "currency", "paid_by", "tx", "desk"], ...sorted].map((r) => r.map(qcsv).join(",")).join("\n") + "\n";
    if (file) { writeFileSync(file, csv); say(`${sorted.length} payments written to ${file}`); } else process.stdout.write(csv);
    const unknownRef = sorted.filter((r) => !r[3]).length;
    if (unknownRef) console.error(`${unknownRef} payment(s) with no invoice in your inbox: check them`);
  },

  /**
   * Move this company from an InvoiceDeskV2 to an InvoiceDeskV3: deploy it, copy the vendors, the agent and
   * its limits, move the allowance, switch the agent off on the old desk, and relink the agent's key to the
   * new desk's pay. The old desk stays in desk.json ("previous"), so export keeps its history.
   */
  async upgrade(...args) {
    const keepOld = args.includes("--keep-old"), d = D(); if (!d.invoiceDesk) fail("no desk yet: node desk.mjs setup (new desks are already V4)");
    if (d.version === 4) return say(`already InvoiceDeskV4 at ${d.invoiceDesk}`);
    const o = await account("owner"), aa = await account("agentacct"), old = d.invoiceDesk, oldVersion = d.version ?? 2, oi = new Interface(art(d).abi);
    chain.ensureRoleKey("agentsigner");
    const sg = await account("agentsigner");
    const lim = await view(old, oi, "limits", [o.evmAddr, FUSD]), [allow] = await view(FUSD, ERC20, "allowance", [o.evmAddr, old]);
    const vendors = [];
    for (const v of Object.keys(d.vendors ?? {})) if ((await view(old, oi, "approved", [o.evmAddr, v]))[0]) vendors.push(v);
    say(`upgrading ${old} (V${oldVersion}) to InvoiceDeskV4: ${vendors.length} vendor(s), limits ${fusd(lim[0])}/${fusd(lim[1])}, allowance ${fusd(allow)}`);
    say("1. the agent's ML-DSA-87 signer: fee money and its key on chain");
    if (BigInt(await balance(sg.cosmos)) < toUqor("0.05")) {
      const r = await broadcast(o, [bankSend(o.cosmos, sg.cosmos, toUqor("0.3"))], "leash desk: fee money for the agent signer");
      if (r.code) fail(`funding the signer was refused: ${r.rawLog}`);
      await sleep(5000);
    }
    if (!(await registerPqc("agentsigner"))) say("  already registered");
    say("2. deploy InvoiceDeskV4 (its own one-transaction window)");
    const { addr, block, hash } = await companyWindow(null, 1, async (w) => {
      const c = await new ContractFactory(ART4.abi, ART4.bytecode, w).deploy(); const rc = await c.deploymentTransaction().wait();
      return { addr: await c.getAddress(), block: rc.blockNumber, hash: rc.hash };
    });
    say(`  deployed at ${addr}           ${hash}`);
    save({ previous: [...(d.previous ?? []), { version: oldVersion, invoiceDesk: old, deployBlock: d.deployBlock, deployedAt: d.deployedAt }], version: 4, invoiceDesk: addr, deployBlock: block, deployTx: hash, deployedAt: new Date().toISOString(), upgradedAt: new Date().toISOString() });
    say("3. the same settings on the new desk, and the agent's signer (a window scoped to it and fUSD)");
    await companyWindow([addr, FUSD], vendors.length + 4, async (w) => {
      const c = new Contract(addr, ART4.abi, w);
      for (const v of vendors) await sendEvm(`approveVendor(${d.vendors[v]})`, c.approveVendor(v));
      await sendEvm("setAgent(agent account)", c.setAgent(aa.evmAddr, true));
      await sendEvm("setAgentSigner(ML-DSA-87)", c.setAgentSigner(aa.evmAddr, sg.evmAddr));
      await sendEvm(`setLimit(${formatUnits(lim[0], 6)}, ${formatUnits(lim[1], 6)})`, c.setLimit(FUSD, lim[0], lim[1]));
      await sendEvm(`fUSD.approve(new desk, ${formatUnits(allow, 6)})`, new Contract(FUSD, ERC20, w).approve(addr, allow));
    });
    if (keepOld) say("4. the old desk stays as it is (--keep-old): its records can still be checked against it");
    else await say("4. the old desk: the agent off, its allowance to zero (a window scoped to it and fUSD)");
    if (!keepOld) await companyWindow([old, FUSD], 2, async (w) => {
      await sendEvm("old desk: setAgent(agent, false)", new Contract(old, ARTS[oldVersion].abi, w).setAgent(aa.evmAddr, false));
      await sendEvm("fUSD.approve(old desk, 0)", new Contract(FUSD, ERC20, w).approve(old, 0));
    });
    say("5. relink the agent's key to the new desk's pay");
    await cmds.agent("link", d.agentRule?.hours ?? "168");
    say(`\ndone: InvoiceDeskV4 at ${addr}. The agent's payments now also need its ML-DSA-87 signature. Tell your vendors the new desk address.`);
  },

  /**
   * The Desk Console's local signer: https://eltociear.github.io/invoice-leash/app.html talks to this server
   * on 127.0.0.1, and every action runs here with your own hybrid (secp256k1 + ML-DSA-87) keys. The keys
   * never leave this machine. Only the console's origin may call it, with the token printed below.
   */
  async serve(port = "8742") {
    const { createServer } = await import("node:http");
    const { randomBytes } = await import("node:crypto");
    const { tmpdir } = await import("node:os");
    const token = process.env.LEASH_SERVE_TOKEN ?? randomBytes(16).toString("hex");
    const ALLOWED = new Set(["https://eltociear.github.io", "http://127.0.0.1:8765", "http://localhost:8765", ...(process.env.LEASH_SERVE_ORIGIN ? [process.env.LEASH_SERVE_ORIGIN] : [])]);
    let busy = Promise.resolve();
    const run = (fn) => { // one action at a time, with its output captured
      const p = busy.then(async () => { sink = []; try { const value = await fn(); return { ok: true, log: sink.join("\n"), value }; } catch (e) { return { ok: false, log: sink.join("\n"), error: e.message || String(e) }; } finally { sink = null; } });
      busy = p.catch(() => {}); return p;
    };
    const snapshot = async () => {
      const o = await account("owner"), aa = await account("agentacct"), g = await account("gas"), d = D();
      const snap = { company: o.cosmos, companyEvm: o.evmAddr, qor: fmt(await balance(o.cosmos)), feeWallet: fmt(await balance(g.cosmos)), agentAccount: aa.cosmos, desk: d.invoiceDesk ?? null, version: d.version ?? (d.invoiceDesk ? 2 : null), vendors: d.vendors ?? {} };
      if (d.invoiceDesk) {
        const [[bal], [allow], lim, [left], [on]] = await Promise.all([view(FUSD, ERC20, "balanceOf", [o.evmAddr]), view(FUSD, ERC20, "allowance", [o.evmAddr, d.invoiceDesk]), view(d.invoiceDesk, desk, "limits", [o.evmAddr, FUSD]), view(d.invoiceDesk, desk, "remainingToday", [o.evmAddr, FUSD]), view(d.invoiceDesk, desk, "isAgent", [o.evmAddr, aa.evmAddr])]);
        const coin = ((await chain.getJson(`/cosmos/bank/v1beta1/balances/${o.cosmos}`)).balances ?? []).find((b) => b.denom.toLowerCase() === `erc20:${FUSD}`.toLowerCase());
        const link = (await links(aa.cosmos)).find((a) => a.pubkeyHex.toLowerCase() === hex(agentKey().pk));
        Object.assign(snap, { float: fusd(bal), treasury: fusd(coin?.amount ?? 0), allowance: fusd(allow), perPayment: fusd(lim[0]), daily: fusd(lim[1]), leftToday: fusd(left), agentOn: on,
          agentKey: !link ? "not linked" : link.revoked ? "revoked" : Number(link.expiryUnix) * 1000 < Date.now() ? "expired" : `linked until ${new Date(Number(link.expiryUnix) * 1000).toISOString().slice(0, 16)}Z` });
      }
      return snap;
    };
    const routes = {
      "GET /status": async () => { const r = await run(() => cmds.status()); return { ...r, value: await snapshot(), next: (r.log.match(/next: (.*)$/m) ?? [])[1] }; },
      "GET /triage": async () => { const r = await run(() => cmds.triage()); return { ...r, value: existsSync(TRIAGE) ? JSON.parse(readFileSync(TRIAGE, "utf8")).items : [] }; },
      "POST /run": () => run(() => cmds.run()),
      "POST /pay": (q) => run(() => cmds.pay(q.get("n"))),
      "POST /agent": (q) => run(() => cmds.agent(q.get("do"), q.get("hours") ?? "168")),
      "POST /freeze": () => run(() => cmds.freeze()),
      "POST /unfreeze": () => run(() => cmds.unfreeze()),
      "POST /vendor": (q) => run(() => cmds.vendor(q.get("do"), q.get("address"), q.get("name") ?? "")),
      "POST /limits": (q) => run(() => cmds.limits(q.get("per"), q.get("daily"))),
      "POST /treasury": (q) => run(() => cmds.treasury(q.get("float") ?? "400")),
      "POST /inbox": (q, body) => run(async () => { const f = join(tmpdir(), `leash-inbox-${Date.now()}.json`); writeFileSync(f, body); await cmds.inbox("add", f); }),
      "GET /export": async () => { const f = join(tmpdir(), `leash-export-${Date.now()}.csv`); const r = await run(() => cmds.export(f)); return { ...r, value: existsSync(f) ? readFileSync(f, "utf8") : "" }; },
    };
    createServer(async (req, res) => {
      const origin = req.headers.origin;
      if (origin && ALLOWED.has(origin)) {
        res.setHeader("access-control-allow-origin", origin);
        res.setHeader("access-control-allow-headers", "authorization, content-type");
        res.setHeader("access-control-allow-methods", "GET, POST");
        if (req.headers["access-control-request-private-network"]) res.setHeader("access-control-allow-private-network", "true"); // Chrome: a public page asking a local server
      }
      if (req.method === "OPTIONS") return res.end();
      const send = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
      if (origin && !ALLOWED.has(origin)) return send(403, { ok: false, error: `origin ${origin} may not use this desk` });
      if (req.headers.authorization !== `Bearer ${token}`) return send(401, { ok: false, error: "wrong or missing token: use the link desk.mjs serve printed" });
      const u = new URL(req.url, "http://127.0.0.1"), route = routes[`${req.method} ${u.pathname}`];
      if (!route) return send(404, { ok: false, error: `no route ${req.method} ${u.pathname}` });
      let body = ""; for await (const c of req) body += c;
      try { send(200, await route(u.searchParams, body)); } catch (e) { send(500, { ok: false, error: e.message }); }
    }).listen(Number(port), "127.0.0.1", () => {
      console.log(`Desk Console signer for ${D().invoiceDesk ?? "(no desk yet)"} on http://127.0.0.1:${port}`);
      console.log(`open: https://eltociear.github.io/invoice-leash/app.html#local=http://127.0.0.1:${port}&token=${token}`);
      console.log("Your keys stay on this machine. Ctrl-C to stop.");
    });
    await new Promise(() => {});
  },

  async mcp() {
    say(JSON.stringify({ mcpServers: { "invoice-leash": { command: "node", args: [new URL("./mcp/server.mjs", import.meta.url).pathname], env: { LEASH_DIR: HOME, LEASH_DEPLOYMENT: join(HOME, "desk.json"), LEASH_INBOX2: INBOX } } } }, null, 2));
    console.error("\nsave as .mcp.json (or pass with claude --mcp-config). The server holds only the agent's key; the desk and the chain hold the limits.");
  },
};

const [cmd, ...args] = process.argv.slice(2);
if (!cmds[cmd]) { say(readFileSync(new URL(import.meta.url), "utf8").split("\n").filter((l) => l.startsWith("//")).slice(0, 32).map((l) => l.slice(3)).join("\n")); process.exit(cmd ? 1 : 0); }
try { await cmds[cmd](...args); } catch (e) { console.error(`\n${e.message || e.shortMessage || e.code || e}`); if (process.env.LEASH_DEBUG) console.error(e); process.exitCode = 1; }
