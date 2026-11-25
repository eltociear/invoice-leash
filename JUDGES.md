# Judging Invoice Leash in five minutes

Everything here can be checked without trusting us: no keys, no test tokens, no account.

## 1. Start the checks (three to four minutes; read on while they run)

```sh
git clone --recurse-submodules https://github.com/eltociear/invoice-leash && cd invoice-leash
npm install && npm run verify
```

Every claim in the README is re-checked against the live `qorechain-diana` testnet: the deployed
desks are byte-for-byte this source (v1, V2, both V3 desks and the live V4 desk), every recorded transaction is re-read, every attack is replayed
against the real contracts, and the live agent's log is checked link by link. The last run, readable:
[`runs/verify-latest.txt`](runs/verify-latest.txt); machine-readable, one entry per check:
[`runs/verify-latest.json`](runs/verify-latest.json). CI runs it every day.

## 2. Try to break it yourself (one minute)

- [Attack lab §6, Shor's gift](https://eltociear.github.io/invoice-leash/lab.html#shor): an account
  whose secp256k1 private key we publish. Your browser signs a transaction with it and sends it. The chain
  refuses: the account also has an ML-DSA-87 key, and that one is secret.
- [Attack lab §7](https://eltociear.github.io/invoice-leash/lab.html#v4): ask the live InvoiceDeskV4 as the
  agent with its classical key alone, or with an ML-DSA-87 key your browser makes: `BadAgentSignature`.
  As the company: it would pay.
- [Attack lab §1–4](https://eltociear.github.io/invoice-leash/lab.html): change any field of a real
  invoice, or sign one with an ML-DSA-87 key your browser makes, and ask the real desk.

## 3. Watch it run (one minute)

- [The Desk Console](https://eltociear.github.io/invoice-leash/app.html): pick a desk and read it live
  from the chain (no wallet). With `node desk.mjs serve`, the same page runs your own desk: approve a
  vendor, sign an invoice in the page with ML-DSA-87, triage, let the agent pay, freeze, export. It was
  driven end to end in a real browser on a V4 desk ([`runs/console-e2e-v4.json`](runs/console-e2e-v4.json); on V3: [`runs/console-e2e.json`](runs/console-e2e.json)).
- [The live agent](https://eltociear.github.io/invoice-leash/#live): in GitHub Actions, with its key in
  GitHub Secrets and a decider that obeys every email. On InvoiceDeskV4 each day the genuine invoice is paid
  and four attempts are refused, among them the agent's classical key alone (`BadAgentSignature`). The
  first V4 day ran on GitHub's runner ([run](https://github.com/eltociear/invoice-leash/actions/runs/45554630612), committed by the job: [`3df2c33`](https://github.com/eltociear/invoice-leash/commit/3df2c33)); see
  [`runs/live/`](runs/live/) for which days ran where.
- [2,000 dry-run attacks on the live V4 desk](https://eltociear.github.io/invoice-leash/#campaign) (half with the agent's key but not its signer: all `BadAgentSignature`), and
  how three Claude models behaved when told to obey a forged CFO (a test of the models, not of the leash).

## 4. Read the one idea (one minute)

[What we found](README.md#what-we-found-a-spending-rule-bounds-amounts-not-destinations): a QoreChain
spending rule bounds amounts, not destinations. So the agent gets its own account, which holds nothing,
and may call one function. The money moves only through a contract that checks the vendor's ML-DSA-87
signature with QoreChain's precompile.

## The rubric, and where to look

| Criterion | Evidence |
|---|---|
| Works (25) | `npm run verify`; 100% coverage of the contracts, 17 properties proved with Halmos ([`runs/halmos.txt`](runs/halmos.txt)); the live agent; a third company set up from nothing with `desk.mjs` on InvoiceDeskV4, and the Desk Console driven in a browser on it ([`runs/own-company-v4/`](runs/own-company-v4/), [`runs/console-e2e-v4.json`](runs/console-e2e-v4.json)); a second, upgraded to V3 ([`runs/own-company-v3/`](runs/own-company-v3/)); the V4 attack campaign ([`runs/campaign-v4.json`](runs/campaign-v4.json)) |
| QoreChain tech (25) | the PQC precompiles in the contract; hybrid accounts; an authenticator with a spending rule; EVM windows with `allowed_targets`; `MsgExecuteEVM`; QoreSign; QoreSeal and the KEM registry; `MsgConvertCoin` / `MsgConvertERC20`; the AMM; QoreScan; QoreChain's MCP server; eleven measured notes for builders, each with its transaction ([CHAIN_NOTES.md](CHAIN_NOTES.md)) |
| Post-quantum (20) | [QUANTUM_READINESS.md](QUANTUM_READINESS.md): every algorithm in the system and what a quantum computer does to it; the Q-Day drill; Shor's gift; on InvoiceDeskV4 the agent's own classical key pays nothing its ML-DSA-87 signer did not sign ([live](runs/probes/v4-agent-sig.json)), the signer signs nothing the desk would refuse, and none of the 57 public agent signatures would pay again ([sweep](runs/signature-sweep.json)); no classical-only lane on the chain at all ([record](runs/probes/no-pq-evm.json)) |
| Originality (15) | the finding above; an agent whose key is kept where it can leak, on purpose |
| Clarity (15) | the [site](https://eltociear.github.io/invoice-leash/), the [video](https://youtu.be/dyHS4OQdb9Y), [GETTING_STARTED.md](GETTING_STARTED.md), [THREAT_MODEL.md](THREAT_MODEL.md) |

## The chain's own words

What QoreChain answered when each attack was tried, quoted from the recorded runs (account addresses
shortened). The chain's refusals are its own text. The desk's refusals are the contract's revert data,
which the chain stores in each transaction's result: `npm run verify` reads it back from the chain and
decodes it with the contract's ABI, for every V4 refusal.

| Attack | Who refused | QoreChain's answer, verbatim | Evidence |
|---|---|---|---|
| A transaction signed with the classical key alone (Q-Day) | the chain, before any block | `account … has a registered PQC key and must include the hybrid signature extension (hybrid mode: required): hybrid PQC signature required` (code 20) | [`runs/qday-drill.json`](runs/qday-drill.json) |
| An EVM transaction with no window open | the chain | `account … has no open EVM authorisation window; open one with MsgOpenEVMWindow, signed on the Cosmos lane with the account's post-quantum key` | [`runs/qday-drill.json`](runs/qday-drill.json), lab §6 |
| Replacing a vendor's ML-DSA-87 key, or the agent's ML-KEM key, without the PQC key | the chain | `register and migrate need its hybrid signature: PQC key maintenance from a keyed account needs the hybrid signature` (code 234) | [`runs/qday-drill.json`](runs/qday-drill.json) |
| Inside a window, a call to a target it does not list | the chain | `the EVM authorisation window for … does not admit this transaction: the window does not list 0x97143B77… as an allowed recipient` | [`runs/probes/window.json`](runs/probes/window.json) |
| Inside a window, past its transaction or value cap | the chain | `does not admit this transaction (remaining: 89 blocks, 0 transactions, 87250 uqor; this transaction needs 12750 uqor): EVM authorisation window exhausted` | [`runs/probes/window-caps.json`](runs/probes/window-caps.json) |
| The agent's key asks for a direct fUSD transfer (a prompt injection) | the chain's spending rule | `a linked key with a spending rule may call 0x97143B77… with data only if the rule lists the call in allowed_evm_calls … authenticator not permitted for this action` | [live log](runs/live/log.jsonl) |
| The agent's classical key alone, on InvoiceDeskV4 (as after Q-Day) | InvoiceDeskV4, via the ML-DSA-87 precompile | `BadAgentSignature` | [`runs/probes/v4-agent-sig.json`](runs/probes/v4-agent-sig.json) |
| An ordinary EVM wallet with no post-quantum key | the chain | `has no usable registered post-quantum key; the EVM lane requires one, like every other lane` | [`runs/probes/no-pq-evm.json`](runs/probes/no-pq-evm.json) |
| A forged invoice, or one whose amount was edited | InvoiceDeskV4, via the ML-DSA-87 precompile | `BadSignature` | [live log](runs/live/log.jsonl), [`runs/v4-compromised.json`](runs/v4-compromised.json) |
| An invoice from a vendor the company never approved | InvoiceDeskV4 | `UnknownVendor` | [`runs/v4-compromised.json`](runs/v4-compromised.json) |
| Over the agent's limit; a replay | InvoiceDeskV4 | `OverPerPaymentLimit`, `OverDailyLimit`, `AlreadyPaid` | [`runs/v4-compromised.json`](runs/v4-compromised.json) |
| Past due (agent); zero amount | InvoiceDeskV4 (dry run, then settled in person); InvoiceDeskV3 on chain | `PastDue`, `ZeroAmount` | [`runs/own-company-v4/triage.log`](runs/own-company-v4/triage.log); [`runs/own-company-v3/`](runs/own-company-v3/) |
| A refused payment's agent signature, sent again later by the agent's classical key alone | the signer, before signing; the company, by rotating it | the signer signs only what the desk would pay right then (`signerMay`); `desk.mjs signer rotate` voids every signature the old signer made | [`runs/signature-sweep.json`](runs/signature-sweep.json): 57 public agent signatures, none would pay; [`runs/own-company-v4/signer-rotate.log`](runs/own-company-v4/signer-rotate.log) |

## What it does not stop

Read [THREAT_MODEL.md](THREAT_MODEL.md#what-invoice-leash-does-not-stop) and
[GETTING_STARTED.md](GETTING_STARTED.md#what-it-does-not-do-yet). In short: within its limits, the agent
can pay genuine invoices from approved vendors that the company did not want paid; a compromised company
key can do anything; it runs on the testnet with fUSD, and vendors must be on QoreChain.
