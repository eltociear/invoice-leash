#!/usr/bin/env node
// vendor.mjs: the vendor's side of Invoice Leash. Make a post-quantum key, register it on chain, and sign
// invoices your customers' desks will pay (QoreChain testnet qorechain-diana).
//
// Your key lives in $LEASH_VENDOR_HOME (default ~/.config/leash-vendor/keys.env, mode 600), on your machine
// only. Your customer never holds it; they approve your address, and their desk checks your signature
// against the ML-DSA-87 key you registered.
//
//   node vendor.mjs init                     make your keys; prints the address to fund (about 1 QOR, faucet)
//   node vendor.mjs register                 register your ML-DSA-87 key on chain (with proof of possession)
//   node vendor.mjs status                   your address and key, as the chain sees them
//   node vendor.mjs sign --desk <0x…> --payer <0x…|qor1…> --amount <fUSD> --ref <invoice number> --due <YYYY-MM-DD>
//                        [--seal-to <qor1… of the payer's agent account>] [--subject "…"] [--out invoice.json]
//                                            sign an invoice; with --seal-to it is sealed with ML-KEM-1024 so only
//                                            the payer's agent can read it. Send the file to the customer.
import { homedir } from "node:os";
import { join } from "node:path";
import { existsSync, mkdirSync, writeFileSync, chmodSync } from "node:fs";

const HOME = process.env.LEASH_VENDOR_HOME ?? join(homedir(), ".config", "leash-vendor");
process.env.LEASH_DIR = HOME;
const sdk = await import("@qorechain/sdk");
const { getAddress, isAddress } = await import("ethers");
const chain = await import("./lib/chain.mjs");
const { CHAIN_ID, REST, account, balance, broadcast, fmt } = chain;
const { FUSD, signInvoiceV2, invoiceFacts } = await import("./lib/invoices.mjs");
const say = (s) => console.log(s), fail = (s) => { throw new Error(s); };
const opt = (args, name, dflt) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : dflt; };
const evmOf = (a) => (isAddress(a) ? getAddress(a) : getAddress(sdk.qorToEvm(a)));

const cmds = {
  async init() {
    mkdirSync(HOME, { recursive: true, mode: 0o700 });
    const KEYS = join(HOME, "keys.env");
    if (!existsSync(KEYS)) { writeFileSync(KEYS, "# Invoice Leash vendor key. QoreChain TESTNET only. Keep this file private.\n", { mode: 0o600 }); chmodSync(KEYS, 0o600); }
    chain.ensureRoleKey("vendor");
    const v = await account("vendor");
    say(`keys: ${KEYS} (mode 600). Back it up.\n\nyour address  ${v.cosmos}  (EVM ${v.evmAddr})\nfund it with about 1 QOR (faucet), then: node vendor.mjs register`);
  },
  async register() {
    const v = await account("vendor");
    if ((await sdk.fetchPqcStatus({ rest: REST, address: v.cosmos })).registered) return say("your ML-DSA-87 key is already registered. Give your customers this address: " + v.evmAddr);
    if (BigInt(await balance(v.cosmos)) === 0n) fail(`${v.cosmos} holds no QOR; fund it (faucet) first`);
    const pop = sdk.signProofOfPossession({ chainId: CHAIN_ID, account: v.cosmos, keypair: v.pqc });
    const r = await broadcast(v, [sdk.buildRegisterPqcKeyMsg(v.cosmos, { pqcKeypair: v.pqc, proofOfPossession: pop })], "leash vendor: register ML-DSA-87", "classical");
    if (r.code) fail(`refused: ${r.rawLog}`);
    say(`ML-DSA-87 key registered  ${r.transactionHash}\nGive your customers this address to approve: ${v.evmAddr}`);
  },
  async status() {
    const v = await account("vendor"), st = await sdk.fetchPqcStatus({ rest: REST, address: v.cosmos });
    say(`address   ${v.cosmos}  (EVM ${v.evmAddr})\nbalance   ${fmt(await balance(v.cosmos))}\nML-DSA-87 ${st.registered ? "registered" : "NOT registered: node vendor.mjs register"}`);
  },
  async sign(...args) {
    const v = await account("vendor");
    const desk = evmOf(opt(args, "desk") ?? fail("--desk <the customer's InvoiceDeskV2 address>"));
    const payer = evmOf(opt(args, "payer") ?? fail("--payer <the customer's company address>"));
    const amount = opt(args, "amount") ?? fail("--amount <fUSD>"), ref = opt(args, "ref") ?? fail("--ref <your invoice number>");
    const due = opt(args, "due") ?? fail("--due <YYYY-MM-DD>"), dueBy = Math.floor(Date.parse(`${due}T23:59:59Z`) / 1000);
    if (!Number.isSafeInteger(dueBy) || dueBy * 1000 < Date.now()) fail(`--due must be a date in the future (got ${due})`);
    if (!(await sdk.fetchPqcStatus({ rest: REST, address: v.cosmos })).registered) fail("register your key first: node vendor.mjs register (otherwise no desk can check your signature)");
    const invoice = signInvoiceV2(v, { desk, payer, vendor: v.evmAddr, token: FUSD, fusd: amount, ref, dueBy });
    const subject = opt(args, "subject", `Invoice ${ref}`), sealTo = opt(args, "seal-to");
    let mail = { from: v.evmAddr, subject, body: `Invoice ${ref}: ${invoiceFacts(invoice).amount}, due ${due}. Signed with ML-DSA-87.`, invoice };
    if (sealTo) {
      const { sealInvoice } = await import("./lib/sealed.mjs");
      mail = { from: v.evmAddr, subject, body: "Invoice attached, sealed to your agent account's ML-KEM-1024 key.", sealed: await sealInvoice(sealTo, invoice) };
    }
    const out = opt(args, "out", `${ref.replace(/[^A-Za-z0-9._-]/g, "_")}.json`);
    writeFileSync(out, JSON.stringify(mail, null, 2) + "\n");
    say(`signed ${ref}: ${invoiceFacts(invoice).amount} to ${payer} through desk ${desk}, due ${due}${sealTo ? `, sealed to ${sealTo}` : ""}\nwrote ${out}: send it to your customer (they run: node desk.mjs inbox add ${out})`);
  },
};

const [cmd, ...args] = process.argv.slice(2);
if (!cmds[cmd]) { const { readFileSync } = await import("node:fs"); say(readFileSync(new URL(import.meta.url), "utf8").split("\n").filter((l) => l.startsWith("//")).map((l) => l.slice(3)).join("\n")); process.exit(cmd ? 1 : 0); }
try { await cmds[cmd](...args); } catch (e) { console.error(`\n${e.message}`); process.exitCode = 1; }
