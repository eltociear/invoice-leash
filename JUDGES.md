# Judging Invoice Leash in five minutes

Everything here can be checked without trusting us: no keys, no test tokens, no account.

## 1. Run the checks (about two minutes)

```sh
git clone --recurse-submodules https://github.com/eltociear/invoice-leash && cd invoice-leash
npm install && npm run verify
```

Every claim in the README is re-checked against the live `qorechain-diana` testnet: the deployed
desks are byte-for-byte this source (v1, V2, and both V3 desks), every recorded transaction is re-read, every attack is replayed
against the real contracts, and the live agent's log is checked link by link. The last run, readable:
[`runs/verify-latest.txt`](runs/verify-latest.txt); machine-readable, one entry per check:
[`runs/verify-latest.json`](runs/verify-latest.json). CI runs it every day.

## 2. Try to break it yourself (one minute)

- [Attack lab §6, Shor's gift](https://eltociear.github.io/invoice-leash/lab.html#shor): an account
  whose secp256k1 private key we publish. Your browser signs a transaction with it and sends it. The chain
  refuses: the account also has an ML-DSA-87 key, and that one is secret.
- [Attack lab §1–4](https://eltociear.github.io/invoice-leash/lab.html): change any field of a real
  invoice, or sign one with an ML-DSA-87 key your browser makes, and ask the real desk.

## 3. Watch it run (one minute)

- [The Desk Console](https://eltociear.github.io/invoice-leash/app.html): pick a desk and read it live
  from the chain (no wallet). With `node desk.mjs serve`, the same page runs your own desk: approve a
  vendor, sign an invoice in the page with ML-DSA-87, triage, let the agent pay, freeze, export. It was
  driven end to end in a real browser ([`runs/console-e2e.json`](runs/console-e2e.json)).
- [The live agent](https://eltociear.github.io/invoice-leash/#live): on a daily schedule in GitHub Actions
  (first run 2026-11-24 with only CI's keys; scheduled from 2026-11-25), unattended, with its key in GitHub Secrets and a decider that obeys every email. Each day the genuine
  invoice is paid and three attacks are refused ([`runs/live/`](runs/live/)).
- [2,000 dry-run tamperings against the live desk](https://eltociear.github.io/invoice-leash/#campaign), and
  how three Claude models behaved when told to obey a forged CFO (a test of the models, not of the leash).

## 4. Read the one idea (one minute)

[What we found](README.md#what-we-found-a-spending-rule-bounds-amounts-not-destinations): a QoreChain
spending rule bounds amounts, not destinations. So the agent gets its own account, which holds nothing,
and may call one function. The money moves only through a contract that checks the vendor's ML-DSA-87
signature with QoreChain's precompile.

## The rubric, and where to look

| Criterion | Evidence |
|---|---|
| Works (25) | `npm run verify`; 100% coverage of the contracts, 17 properties proved with Halmos ([`runs/halmos.txt`](runs/halmos.txt)); the live agent; a second company set up from nothing with `desk.mjs` and upgraded to InvoiceDeskV3 ([`runs/own-company/`](runs/own-company/), [`runs/own-company-v3/`](runs/own-company-v3/)); the attack campaign ([`runs/campaign.json`](runs/campaign.json)) |
| QoreChain tech (25) | the PQC precompiles in the contract; hybrid accounts; an authenticator with a spending rule; EVM windows with `allowed_targets`; `MsgExecuteEVM`; QoreSign; QoreSeal and the KEM registry; `MsgConvertCoin` / `MsgConvertERC20`; the AMM; QoreScan; QoreChain's MCP server |
| Post-quantum (20) | [QUANTUM_READINESS.md](QUANTUM_READINESS.md): every algorithm in the system and what a quantum computer does to it; the Q-Day drill; Shor's gift |
| Originality (15) | the finding above; an agent whose key is kept where it can leak, on purpose |
| Clarity (15) | the [site](https://eltociear.github.io/invoice-leash/), the [video](https://youtu.be/K3Teb5sO8JU), [GETTING_STARTED.md](GETTING_STARTED.md), [THREAT_MODEL.md](THREAT_MODEL.md) |

## The chain's own words

What QoreChain answered when each attack was tried, quoted from the recorded runs (account addresses
shortened). These are the chain's messages, not ours.

| Attack | Who refused | QoreChain's answer, verbatim | Evidence |
|---|---|---|---|
| A transaction signed with the classical key alone (Q-Day) | the chain, before any block | `account … has a registered PQC key and must include the hybrid signature extension (hybrid mode: required): hybrid PQC signature required` (code 20) | [`runs/qday-drill.json`](runs/qday-drill.json) |
| An EVM transaction with no window open | the chain | `account … has no open EVM authorisation window; open one with MsgOpenEVMWindow, signed on the Cosmos lane with the account's post-quantum key` | [`runs/qday-drill.json`](runs/qday-drill.json), lab §6 |
| Replacing a vendor's ML-DSA-87 key, or the agent's ML-KEM key, without the PQC key | the chain | `register and migrate need its hybrid signature: PQC key maintenance from a keyed account needs the hybrid signature` (code 234) | [`runs/qday-drill.json`](runs/qday-drill.json) |
| Inside a window, a call to a target it does not list | the chain | `the EVM authorisation window for … does not admit this transaction: the window does not list 0x97143B77… as an allowed recipient` | [`runs/probes/window.json`](runs/probes/window.json) |
| Inside a window, past its transaction or value cap | the chain | `does not admit this transaction (remaining: 89 blocks, 0 transactions, 87250 uqor; this transaction needs 12750 uqor): EVM authorisation window exhausted` | [`runs/probes/window-caps.json`](runs/probes/window-caps.json) |
| The agent's key asks for a direct fUSD transfer (a prompt injection) | the chain's spending rule | `a linked key with a spending rule may call 0x97143B77… with data only if the rule lists the call in allowed_evm_calls … authenticator not permitted for this action` | [live log](runs/live/log.jsonl) |
| A forged invoice, or one whose amount was edited | InvoiceDeskV3, via the ML-DSA-87 precompile | `BadSignature` | [live log](runs/live/log.jsonl), [`runs/campaign.json`](runs/campaign.json) |
| An invoice from a vendor the company never approved | InvoiceDeskV3 | `UnknownVendor` | [`runs/campaign.json`](runs/campaign.json) |
| Over the agent's limit; past due (agent); zero amount | InvoiceDeskV3 | `OverPerPaymentLimit`, `OverDailyLimit`, `PastDue`, `ZeroAmount` | [`runs/own-company-v3/`](runs/own-company-v3/) |

## What it does not stop

Read [THREAT_MODEL.md](THREAT_MODEL.md#what-invoice-leash-does-not-stop) and
[GETTING_STARTED.md](GETTING_STARTED.md#what-it-does-not-do-yet). In short: within its limits, the agent
can pay genuine invoices from approved vendors that the company did not want paid; a compromised company
key can do anything; it runs on the testnet with fUSD, and vendors must be on QoreChain.
