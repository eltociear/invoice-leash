# Invoice Leash: an invoice agent that stays safe when its model does not

[![Built on QoreChain](https://build.qorechain.io/badge/invoice-leash.svg)](https://build.qorechain.io/p/invoice-leash) [![ci](https://github.com/eltociear/invoice-leash/actions/workflows/ci.yml/badge.svg)](https://github.com/eltociear/invoice-leash/actions/workflows/ci.yml) [![live agent](https://github.com/eltociear/invoice-leash/actions/workflows/live.yml/badge.svg)](https://github.com/eltociear/invoice-leash/actions/workflows/live.yml)

![Invoice Leash: a compromised agent tries every attack; the chain pays only the genuine, in-limit invoices](assets/cover.png)

An AI agent pays a company's invoices on the QoreChain testnet, and we assume from the start that its
model will be fooled and its key stolen. So the agent checks nothing. **Every limit lives on QoreChain or
in the contract, every invoice needs the vendor's post-quantum ML-DSA-87 signature, and every payment
the agent makes needs the agent's own ML-DSA-87 signature too, all verified on chain.** On InvoiceDeskV5,
the live desk since 2026-11-26, the agent's signature covers the whole invoice (its due date included), the
vendor's signature and a deadline minutes away, so it pays exactly one signed invoice, once, soon, or nothing
([live](runs/probes/v5-bindings.json)). The live agent's signer runs on a separate host (its own GitHub
Environment) and signs only what the desk would pay right then.

**Judges: [JUDGES.md](JUDGES.md)** (a five-minute route) · [site](https://eltociear.github.io/invoice-leash/) ·
[Desk Console](https://eltociear.github.io/invoice-leash/app.html) · [attack lab](https://eltociear.github.io/invoice-leash/lab.html) ·
[video](https://youtu.be/evNAZJs4cFg) · `qorechain-diana` testnet only (test tokens have no value) · Post-Quantum AI Agents

> **Check every claim in three to four minutes, with no keys and no test QOR:**
>
> ```sh
> git clone --recurse-submodules https://github.com/eltociear/invoice-leash && cd invoice-leash
> npm install && npm run verify
> ```
>
> 124 checks against the live testnet: the deployed contracts are byte-for-byte this source, every
> recorded transaction is re-read, every recorded attack is asked again (each 2,000-attack campaign: a sample). Last run: [`runs/verify-latest.txt`](runs/verify-latest.txt)
> ([JSON](runs/verify-latest.json)). CI runs it daily, with 215 Foundry tests and 25 invariants.

## In one minute

- **What we found.** We probed our own first design on chain: a QoreChain spending rule bounds
  *amounts*, not *destinations*. A key whose rule allowed only `InvoiceDesk.pay` still sent 0.01 QOR to
  a fresh address ([779FAF6E…](https://explore.qore.network/tx/779FAF6E8871B3FFF1D0D2D129AC904529E78E5198718C1DD630676E05AD4CEC),
  [details](#what-we-found-a-spending-rule-bounds-amounts-not-destinations)). So the agent got its own
  account, which holds no money and may make one call: the desk's `pay`.
- **What that buys.** On the live InvoiceDeskV5, a decider that obeys every email made 16 attempts
  (forgeries, an edited amount, Mallory's own valid invoice, injections, the agent's classical key alone,
  a replay, both limits): only the 3 genuine invoices were paid, 0 to the attacker
  ([`runs/v5-compromised.json`](runs/v5-compromised.json); on V4: [`runs/v4-compromised.json`](runs/v4-compromised.json)).
  2,000 dry-run attacks on each of the V4 and V5 desks: 0 would pay ([`runs/campaign-v5.json`](runs/campaign-v5.json)).
- **After Q-Day.** With four accounts' classical keys alone, 16 attacks were refused before any block. The
  agent's own classical key alone pays nothing its ML-DSA-87 signer did not sign, and on V5 a signature
  pays one exact invoice, once, within 15 minutes: an expired one, a forged copy's and a reissue's were
  refused on chain ([`runs/probes/v5-bindings.json`](runs/probes/v5-bindings.json)). `npm run verify` sends every agent
  signature ever made public again, as the classical key alone: none would pay
  ([`runs/signature-sweep.json`](runs/signature-sweep.json)). An ordinary EVM wallet with no post-quantum key cannot send
  anything on this chain. And one account's classical private key is published: try to take its QOR
  ([lab §6](https://eltociear.github.io/invoice-leash/lab.html#shor)).
- **It runs, and you can run it.** GitHub Actions runs the agent daily with an obey-everything decider
  and its key in GitHub Secrets on purpose; the signer is a separate job in its own Environment
  ([`runs/live/`](runs/live/); [where each day ran](runs/live/README.md#where-each-day-ran): GitHub starts schedules
  late or not at all, so some days were started by hand). `desk.mjs` sets up a desk for your own company;
  two more companies were set up that way from nothing.

## The rubric, and where to look

| Criterion | Evidence |
|---|---|
| **Works** (25) | `npm run verify` (124 checks); the [live agent](runs/live/); [Claude as the agent on the live V5 desk](runs/mcp-v5-claude-final.txt); a [fourth company set up from nothing on V5](runs/own-company-v5/) with `desk.mjs` (a [third on V4](runs/own-company-v4/), with the Desk Console) (and a [second](runs/own-company-v3/), on V3); the [Desk Console](runs/console-e2e-v5.json) driven in a real browser; 100% coverage and 27 Halmos proofs ([`runs/halmos.txt`](runs/halmos.txt)) |
| **QoreChain tech** (25) | the ML-DSA-87 precompiles `0x…0a01`/`0a02` inside the contract; hybrid accounts; an authenticator with a spending rule; EVM windows with `allowed_targets`; `MsgExecuteEVM` relaying; QoreSign; QoreSeal ML-KEM-1024 and the KEM registry; `MsgConvertCoin`/`MsgConvertERC20`; the AMM; QoreScan; QoreChain's MCP server |
| **Post-quantum** (20) | [QUANTUM_READINESS.md](QUANTUM_READINESS.md): every algorithm in the system, the Q-Day drill, Shor's gift, no classical-only lane; on InvoiceDeskV4 and V5 the agent's classical key alone pays nothing its signer did not sign, even inside its own EVM window ([`runs/probes/window-v4.json`](runs/probes/window-v4.json)); its signer runs on a separate host and signs nothing the desk would refuse; none of the 132 public agent signatures would pay again ([sweep](runs/signature-sweep.json)); `desk.mjs signer rotate` voids them all at once; on V5 each signature also expires in minutes and binds the vendor's signature and due date ([live](runs/probes/v5-bindings.json)) |
| **Originality** (15) | the finding above, and the redesign it forced; an agent whose key is kept where it can leak, on purpose |
| **Clarity** (15) | the [site](https://eltociear.github.io/invoice-leash/), [JUDGES.md](JUDGES.md), [GETTING_STARTED.md](GETTING_STARTED.md), [THREAT_MODEL.md](THREAT_MODEL.md), [DECISIONS.md](DECISIONS.md); the track's requirements one by one: [EVIDENCE.md](EVIDENCE.md#the-tracks-requirements-and-where-each-one-is-shown-on-chain) |

## How it works

| | Holds | Can |
|---|---|---|
| **The company** (payer) | its fUSD, in its own account (no vault). Most of it as the bank coin, which moves only with ML-DSA-87; a float as ERC-20 for the desk to pull | approve vendors, name agents, set limits, give the desk an allowance, freeze. Hybrid secp256k1 + **ML-DSA-87** keys |
| **The agent's account** | no fUSD; a little QOR for its own setup fees | one thing, through its QoreChain spending rule: call the desk's `pay`. Its rule lists no denom it holds, so the agent's key moves nothing |
| **The agent's key** | nothing | sign requests for the agent's account (ed25519, linked, expires). A relayer submits them. **On V4 and V5 it is not enough**: see step 2 |
| **The agent's signer** (V4, V5) | nothing | sign each payment with **ML-DSA-87**; the company names this signer to the desk |
| **[`InvoiceDeskV5`](contracts/InvoiceDeskV5.sol)**, the live desk ([`V4`](contracts/InvoiceDeskV4.sol): step 2 without the due date, the vendor's signature and the deadline; [`V3`](contracts/InvoiceDeskV3.sol): no step 2) | nothing (it pulls company → vendor in one call) | pay an invoice for the company only if every check below passes |

What `pay` checks, all on chain, in this order:

1. the caller is the company, or an agent the company named (`NotPayersAgent`)
2. **For an agent: its own ML-DSA-87 signature**, verified with the precompile against the key of the
   signer the company named (`AgentSignerNotSet`, `AgentKeyNotProven`, `BadAgentSignature`). So the
   agent's classical key alone pays nothing its signer did not sign, after Q-Day included
   ([V4, live](runs/probes/v4-agent-sig.json)). **On V5** it signs this desk, payer and agent, the whole
   invoice (its digest: vendor, token, amount, id and due date), the hash of the vendor's signature and a
   deadline the signer sets 15 minutes ahead (`AgentSignatureExpired` after it). So a signature pays one
   exact signed invoice, once, before its deadline: not a forged copy's twin, not a reissue
   ([live](runs/probes/v5-bindings.json)). On V4 it covered vendor, token, amount and id only, with no
   deadline; there the signer signs only what the desk would pay right then (`lib/agent.mjs` `signerMay`,
   on V5 too), and `desk.mjs signer rotate` voids every signature a signer ever made
3. the vendor is on the company's approved list (`UnknownVendor`)
4. the vendor's **ML-DSA-87** key is registered with proof of possession, read live from the PQC module at
   `0x…0a02` (`VendorKeyNotProven`)
5. that key signed exactly these bytes, checked by the PQC precompile `0x…0a01`: domain, chain id, this
   desk, payer, vendor, currency, amount, invoice id, due date (`BadSignature`)
6. a non-zero amount, not paid before by this payer to this vendor (`ZeroAmount`, `AlreadyPaid`)
7. for an agent: not past due, an ERC-20, within the company's per-payment and daily limit
   (`PastDue`, `AgentCannotPayNative`, `OverPerPaymentLimit`, `OverDailyLimit`). The company itself may
   settle an overdue invoice
8. exactly the invoiced amount reaches the vendor (`TransferFailed` otherwise)

Earlier recorded runs used the earlier designs: v1 (QOR, the agent acting as the company, [V1.md](V1.md)),
InvoiceDeskV2 (the same checks, invoice ids per payer, no late settlement) and InvoiceDeskV3 (no agent
signature). The compromised-agent run, the attack campaign and the window probe ran on V4, the live desk
until 2026-11-26; the live agent has used V5 since (`desk.mjs upgrade`, [log](runs/live/upgrade-v5.log)). Every
earlier desk stays deployed and checked; new desks are V5, and `desk.mjs upgrade` moves a V2, V3 or V4 company ([why](DECISIONS.md#5-invoicedeskv3-invoice-numbers-per-vendor-late-invoices-settled-by-the-company)).

## What we found: a spending rule bounds amounts, not destinations

v1 of Invoice Leash let the agent act *as the company's account*, scoped by a QoreChain spending rule
to `InvoiceDesk.pay` with per-payment and daily limits. Probing that design on diana showed the scope
is not what it looks like. Every probe below is one request by the agent's key, re-read by
`npm run verify` ([`runs/probes/probes.json`](runs/probes/probes.json)):

| Rule on the account the agent acts as | The agent's key tries | Chain |
|---|---|---|
| per-tx/daily QOR limits, `allowed_evm_calls = [desk.pay]` | send 0.01 QOR to a fresh address, no call data | **executed** [779FAF6E…](https://explore.qore.network/tx/779FAF6E8871B3FFF1D0D2D129AC904529E78E5198718C1DD630676E05AD4CEC) |
| `allowed_denoms = [fUSD]` with fUSD limits, calls `[InvoiceDeskV2.pay]` | `fUSD.transfer(fresh address, 1)` | **executed** [0A40A451…](https://explore.qore.network/tx/0A40A4513548A433D8B49CF8D32ECEC089AE8F1B7D174AB82B3C67C6D67C91C2) |
| same | send 0.01 QOR | refused: `denom uqor not allowed` [3B496E0E…](https://explore.qore.network/tx/3B496E0EC4F69DFAB62FA2ABC6E3C0A0AB1812D72DA5254956964F0AE18C5608) |
| fUSD **not** listed | `fUSD.transfer(fresh address, 1)` | refused [B9C8C49A…](https://explore.qore.network/tx/B9C8C49ADEA2643A03D643A8A20C3F4D2E393D407EFBAD6523C9E7E0604437EB) |
| fUSD **not** listed | `desk.pay` of a genuine 1 fUSD invoice | refused: *"the call made a token transfer from the account on fUSD, which the rule does not list"* [4F54B0C0…](https://explore.qore.network/tx/4F54B0C09E51590A8761550B807D2E90EE01FB4BB96E3B39C92930DCAA2B6FC9) |
| **v2**: the agent's own account (no fUSD), only fBTC listed (1 satoshi, balance 0) | `desk.pay` of a genuine 1 fUSD invoice, paid from the *company's* account | **executed** [C4C05CA9…](https://explore.qore.network/tx/C4C05CA9BFBD9F245B22C870BFE7CB577C752EADAF1A650D77358CFEEE000591) |

So `allowed_evm_calls` scopes calls *with data*; a key can still move every denom its rule allows,
directly: plain value for QOR, `transfer`/`approve` for a listed ERC-20 (as the SDK's `SpendingRule`
docs say, read closely). And the chain measures ERC-20 outflow from the account on every path. An agent
that acts *as* the payer can therefore either pay nothing in fUSD, or send fUSD anywhere within its
limits, skipping the vendor and signature checks. v1's limits still bounded the damage (1 QOR a
payment, 2.5 a day), but "the agent can only call `pay`" was not true. v2 is the fix: the agent's own
account holds no fUSD and its key may move nothing; the company's money moves only through the desk.

**For other builders on QoreChain** (eleven measured notes, each with its transaction: [CHAIN_NOTES.md](CHAIN_NOTES.md)):
- If your agent acts as an account that holds funds, its spending rule's limits are what bounds it, not
  its call list.
- An EVM call relayed through an authenticator (`MsgExecuteEVM`) leaves no log that `eth_getLogs`
  returns: the block holds no EVM transaction (measured on diana, [D7D404F7…](https://explore.qore.network/tx/D7D404F7155E96952746F75A0D3FD83423CA8C5FF37D4CDD01DFE70CA977AFD4)).
  An indexer that reads events misses every agent payment. `desk.mjs export` reads the relayer's
  transactions and the contract's own state instead.

## The evidence

| What | Result | Record |
|---|---|---|
| InvoiceDeskV5, live: the classical key alone; a signer's signature past its deadline; the signature for a forged copy; the signature for an invoice presented with its reissue (later due date) | all refused (`BadAgentSignature`, `AgentSignatureExpired`); on V4 the last two would have paid ([V4 tests: `test_v4_limit_*`](test/InvoiceDeskV4.t.sol)). The signed payment paid once | [`runs/probes/v5-bindings.json`](runs/probes/v5-bindings.json) |
| A decider that obeys every email, on the live InvoiceDeskV5 (forgeries, edits, Mallory's own valid key, injections, the agent's classical key alone first, a replay, both limits) | 3 genuine invoices paid (17 fUSD), 13 refused, 0 to the attacker | [`runs/v5-compromised.json`](runs/v5-compromised.json) |
| The same, on InvoiceDeskV4 (forgeries, edits, Mallory's own valid key, injections, the agent's classical key alone, a replay, both limits) | 3 genuine invoices paid (17 fUSD), 13 refused, 0 to the attacker | [`runs/v4-compromised.json`](runs/v4-compromised.json), [site](https://eltociear.github.io/invoice-leash/#v4run) |
| The same, recorded earlier on InvoiceDeskV2 | 3 paid, 13 refused, 0 to the attacker | [EVIDENCE.md](EVIDENCE.md#the-demo-inbox-v2-fusd) |
| The live agent, daily in GitHub Actions | each day: the genuine invoice paid; a forgery, a raised amount, a prompt-injected transfer and (on V4 and V5) the agent's classical key alone refused | [`runs/live/`](runs/live/), [site](https://eltociear.github.io/invoice-leash/#live) |
| 2,000 dry-run attacks on the live InvoiceDeskV5: a compromised agent with its signer tampering with a genuine invoice, and the agent's key without its signer holding the signer's signatures for other payments (1,008: missing, tampered, expired, a moved deadline, another due date or vendor signature, V4-style) | 0 would pay; all 1,008 refused (950 `BadAgentSignature`, 58 `AgentSignatureExpired`) | [`runs/campaign-v5.json`](runs/campaign-v5.json) |
| 2,000 dry-run attacks on InvoiceDeskV4 (then live): a compromised agent with its signer tampering with a genuine invoice, and the agent's key without its signer (985 tampered or missing agent signatures) | 0 would pay; every agent-signature attack `BadAgentSignature` | [`runs/campaign-v4.json`](runs/campaign-v4.json) |
| 2,000 dry-run tamperings of 10 kinds, plus 23 signed attacks, against InvoiceDeskV3 | 0 would pay; each refusal the expected one | [`runs/campaign.json`](runs/campaign.json) |
| The Q-Day drill: four accounts' classical keys alone | 16 attacks refused | [QUANTUM_READINESS.md](QUANTUM_READINESS.md) |
| Shor's gift: an account whose classical private key is published | its QOR is still there | [lab §6](https://eltociear.github.io/invoice-leash/lab.html#shor) |
| A fourth company, from nothing, with `desk.mjs`, on InvoiceDeskV5 (2026-11-27) | `setup` in one pass; the agent paid 2 (one sealed), the company 2 in person (past due; over the limit, after `treasury` raised the float the refusal named); an edited copy (`BadSignature`) and a real but unapproved vendor (`UnknownVendor`) refused; then the Desk Console in a real browser: a new agent signer, and the agent paid 2 more with it | [`runs/own-company-v5/`](runs/own-company-v5/), [`runs/console-e2e-v5.json`](runs/console-e2e-v5.json) |
| A third company, from nothing, with `desk.mjs`, on InvoiceDeskV4 | the agent paid 2 (one sealed), the company 2 in person (over the limit; past due); an edited copy and an unapproved vendor refused; the Desk Console driven in a browser on it (the agent paid 2 more); then its signer rotated, and the agent paid with the new one | [`runs/own-company-v4/`](runs/own-company-v4/), [`runs/console-e2e-v4.json`](runs/console-e2e-v4.json) |
| A second company, from nothing, with `desk.mjs`; then `upgrade` to V3 | its own vendors' keys; two vendors' `INV-2001` both paid; an overdue invoice settled in person | [`runs/own-company/`](runs/own-company/), [`runs/own-company-v3/`](runs/own-company-v3/) |
| Claude Code as the agent on the live InvoiceDeskV5, through the MCP server: two genuine invoices, an edited copy, one "in QOR", Mallory asking to be approved, one over the limit, a prompt injection | it dry-ran all six invoices and paid the two genuine ones, 10 fUSD ([1](https://explore.qore.network/tx/2F584A57370117D56CF8C8CECC94DDF3A1E383AD2EF0D653FE5EB7786EAA686E), [2](https://explore.qore.network/tx/FF7334FD57EF3B20A64BDA44240F26DBFEE7398D9CE3FF0405A36376A493C841)); the 15 fUSD one to a human; no `approveVendor`, no transfer | [`runs/mcp-v5-claude-final.txt`](runs/mcp-v5-claude-final.txt) |
| Claude Code through the MCP server; a sealed (ML-KEM-1024) inbox; an obey-everything MCP client | Claude paid only the genuine invoices; the client was refused 12 times | [EVIDENCE.md](EVIDENCE.md#the-mcp-server-and-the-sessions-recorded-through-it) |
| Model behaviour: Haiku, Sonnet and Opus told to obey a forged, unsigned "CFO" | none tried the injected transfers. This tests the models, not the leash | [`runs/models/`](runs/models/) |

## Use it from any agent: the MCP server

`mcp/server.mjs` gives an MCP client (Claude Code, or any other) the agent's tools: `list_inbox`,
`check_invoice` (a dry run of the real desk), `pay_invoice`, `verify_message`, and, on purpose, dangerous
ones like `transfer_fusd` and `send_qor`, which the chain refuses. Read-only for judges, with no keys:

```sh
claude --mcp-config mcp/judge.mcp.json --strict-mcp-config
```

It points at the live InvoiceDeskV5 with a seven-email inbox ([`inbox/inbox-v5-MCP.json`](inbox/inbox-v5-MCP.json)):
ask it to check each invoice. One genuine invoice WOULD PAY; the edited copy, the QOR version, Mallory's own
invoice, the forgery and the over-limit one are each refused with the desk's own reason.

For your own company: `node desk.mjs mcp`. The recorded sessions: [EVIDENCE.md](EVIDENCE.md#the-mcp-server-and-the-sessions-recorded-through-it).

## Run it

- **For your own company:** [GETTING_STARTED.md](GETTING_STARTED.md). `desk.mjs` sets up your desk,
  vendors sign with `vendor.mjs`, and `desk.mjs serve` lets the [Desk Console](https://eltociear.github.io/invoice-leash/app.html)
  run it from the browser while your keys stay on your machine.
- **Replay this demo:** [EVIDENCE.md](EVIDENCE.md#replay-it).

## Tests and proofs

| | |
|---|---|
| Symbolic proofs | 27 properties proved for every input with Halmos (8 for InvoiceDeskV3, 9 for V4, 10 for V5, including "an agent with no named ML-DSA-87 signer pays nothing" and "an agent payment after its signature's deadline never succeeds"), with the signature check stubbed to accept anything, so they hold even against a valid ML-DSA-87 signature ([`runs/halmos.txt`](runs/halmos.txt)) |
| Coverage | 100% of lines, statements, branches and functions, all five contracts ([`runs/coverage.txt`](runs/coverage.txt)) |
| Foundry | 215 Foundry tests with real ML-DSA-87 fixtures, and 25 invariants |
| Mutation | every injected bug caught: V2 14 of 14 mutants, V3: 18 of 18, V4: 25 of 25, V5: 34 of 34, including the agent signature left unchecked or the amount, invoice id, token or agent left out of what it signs ([`runs/mutation.txt`](runs/mutation.txt), [`runs/mutation-v3.txt`](runs/mutation-v3.txt), [`runs/mutation-v5.txt`](runs/mutation-v5.txt), [`runs/mutation-v4.txt`](runs/mutation-v4.txt)) |
| Off chain | `npm test`: invoices, what the agent is shown, page scripts, and every count the documents state |
| Analysis | Slither: informational only ([`runs/slither.txt`](runs/slither.txt)); QoreScan CBOM ([`cbom/`](cbom/)) |

Details: [EVIDENCE.md](EVIDENCE.md#tests). What a payment costs in fees: [EVIDENCE.md](EVIDENCE.md#what-it-costs)
(0.15 QOR on V3, 0.24 QOR on V4 and V5).

## Testnet addresses

| Role | qor1 address | EVM address |
|---|---|---|
| **InvoiceDeskV5**, the live agent's desk since 2026-11-26 | `qor1dgl4zn3twzaunwy9x3uyej2g9rjace5dmst8d6` | `0x6A3f514e2b70bBc9B88534784cc94828e5dC668d` |
| its V4 desk (the live desk until then; the compromised run, the campaign and the window probe) | `qor1ydw6tyt3ez4x9l253rccwr8gau05yzkyf4ehfv` | `0x235dA59171c8aa62fD5488f1870cE8ef1f420ac4` |
| its first desk (V3, kept for the attack campaign) | `qor12j775a0na4avyw7y0u5ureqznm99u7y8fkn83h` | `0x54bdEa75F3eD7ac23bC47F29c1E4029ecA5E7887` |
| its company | `qor1rtgfpxnskja2nhh0lmnqvduxvhzlswa34h84tu` | `0x1ad0909a70b4baa9deeffee606378665c5f83bb1` |
| its agent's account | `qor1fedluhureaezx79ychmnlmvm736vf94sv5rp0k` | `0x4e5bfe5f83cf722378a4c5f73fed9bf474c496b0` |
| its vendor, Daily Hosting Co | `qor1eug4kqp4cepj7v2uyxa9hcfglc8xzum5fjw4fq` | `0xcf115b0035c6432f315c21ba5be128fe0e617374` |
| **InvoiceDeskV3**, the company set up with `desk.mjs` | `qor1smggk09rkf7ascnajc63ndh0cue7yjtqh3pd8p` | `0x86d08B3CA3B27dD8627D963519B6efC733E24960` |
| its first desk (V2, before `upgrade`) | `qor13m7tr6jfct39gsyq6xydtute58whef6tgw5x94` | `0x8efcB1Ea49c2e2544080d188D5F179a1DD7CA74b` |
| that company | `qor1vvxphjk3gw8y425qmumr5l42d5eyzux7ynd0c7` | `0x630c1bcad1438e4aaa80df363a7eaa6d324170de` |
| **InvoiceDeskV2**, the demo's recorded runs and the attack lab | `qor1u5a7d3dedcyelktppwa4dwh9vncjmmucrj25ew` | `0xe53Be6C5b96E099Fd9610bBb56BAe564f12dEf98` |
| its company | `qor16fluqkmkgaqq98hkgdyccny93gwsm32c4awtmg` | `0xd27fc05b764740029ef643498c4c858a1d0dc558` |
| its agent's account | `qor1llw052ph5xqwm2cv2ene8mtqv4lt2epfl5tr3f` | `0xffdcfa2837a180edab0c566793ed60657eb56429` |
| vendors Hostline, Tokenwell | `qor13knjy3pnf45pu052w5mhkta0tyfh2mmf33fjah`, `qor1hw3k0623e89y7r9r0yjxja3z0r2xvwfqz384up` | `0x8da7…6f69`, `0xbba3…3920` |
| attacker Mallory | `qor1xle4mhhmsksk5rqn5ft8mat62pr553sfu97l9t` | `0x37f35ddefb85a16a0c13a2567df57a50474a4609` |
| Shor's gift (classical private key published) | `qor1ven5euj4fcu30euzz28a90wfw3qshsy58tc8ah` | `0x66674cf2554e3917e782128fd2bdc974410bc094` |
| public test vendor (ML-DSA-87 secret key published) | `qor1u6wewn8zg96llz0t7kjlq93cpns58c8tfymmnm` | `0xe69d974ce24175ff89ebf5a5f016380ce143e0eb` |
| InvoiceDesk (v1) | `qor1qqn5x8fnznn89yn7hlvau4a3qqcessfm743l06` | `0x0027431D3314e672927eBfd9de57b1003198413b` |
| fUSD (FestUSD, 6 decimals) | bank denom `erc20:0x9714…63CA` | `0x97143B771D34ddb9130b807b135Ae675A5a963CA` |

v1's earlier owners: [V1.md](V1.md).

## Documents

[JUDGES.md](JUDGES.md) (start here) · [EVIDENCE.md](EVIDENCE.md) (the record) · [GETTING_STARTED.md](GETTING_STARTED.md) ·
[QUANTUM_READINESS.md](QUANTUM_READINESS.md) · [THREAT_MODEL.md](THREAT_MODEL.md) (including what it does not stop) ·
[DECISIONS.md](DECISIONS.md) · [CHAIN_NOTES.md](CHAIN_NOTES.md) (QoreChain, measured) · [AI_USAGE.md](AI_USAGE.md) · [V1.md](V1.md) · [MANDATE.md](MANDATE.md) (a draft mandate profile, written from this project)

## Credits

- Key handling, hybrid broadcasting and the agent-link flow in `lib/chain.mjs` and `leash.mjs` are
  adapted from QoreChain's
  [`build-before-qday/workshop-2/02-pq-agent`](https://github.com/qorechain/build-before-qday/tree/main/workshop-2/02-pq-agent)
  (Apache-2.0).
- [`@qorechain/sdk`](https://www.npmjs.com/package/@qorechain/sdk) (Apache-2.0),
  [`@cosmjs/stargate`](https://www.npmjs.com/package/@cosmjs/stargate),
  [`@noble/curves`](https://www.npmjs.com/package/@noble/curves),
  [`ethers`](https://www.npmjs.com/package/ethers), [`solc`](https://www.npmjs.com/package/solc).
- See [`AI_USAGE.md`](AI_USAGE.md) for how AI was used.

## License

Apache-2.0. See [LICENSE](LICENSE).
