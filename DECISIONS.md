# Design decisions

Each decision, what we considered, and the evidence that settled it. Newest last.

## 1. The agent is assumed compromised

**Decision.** The agent's code checks nothing. It has no limit check, no vendor check and no signature
check. Every limit lives on QoreChain or in the contract.

**Why.** A bill-paying agent reads email written by strangers, so prompt injection is a matter of time,
and its key lives on a server. A design that is safe only while the model behaves is not safe.

**Evidence.** A decider that obeys every email made 16 payment attempts and got only the 3 genuine
invoices paid ([EVIDENCE.md](EVIDENCE.md#the-demo-inbox-v2-fusd)). The live agent runs that decider daily in GitHub Actions
([`runs/live/`](runs/live/)).

## 2. The agent gets its own empty account (v1 → v2)

**Considered.** v1 let the agent act *as* the company's account, bound by a spending rule scoped to
`InvoiceDesk.pay` with per-payment and daily limits.

**Decision.** v2 gives the agent its own account. It holds no fUSD, and its rule lists no denom it holds
and one call, `InvoiceDeskV2.pay`. The money stays in the company's account, and the desk pulls it
through an allowance.

**Why.** We probed v1 on chain. A spending rule bounds *amounts*, not *destinations*: the rule-bound key
sent 0.01 QOR to a fresh address with no call data, and moved a listed ERC-20 with a plain `transfer`
([the finding](README.md#what-we-found-a-spending-rule-bounds-amounts-not-destinations),
[`runs/probes/probes.json`](runs/probes/probes.json)).

## 3. Invoices are signed with ML-DSA-87 and verified on chain

**Considered.** Checking signatures off chain in the agent, or with secp256k1 in the contract.

**Decision.** The vendor signs every invoice with ML-DSA-87. The desk reads the vendor's key from the
chain's PQC module (`0x…0a02`, proof of possession required) and verifies it with the precompile
(`0x…0a01`) at payment time.

**Why.** A check in the agent is a check the attacker controls. A secp256k1 invoice signature is
forgeable after Q-Day, and invoices are long-lived records. Reading the key live means a vendor's key
rotation takes effect at once.

## 4. The signed bytes name everything that matters

**Decision.** Domain, chain id, the desk's address, payer, vendor, currency, amount, invoice id and due
date. The currency was added in v2, after "pay the same invoice in QOR instead" was shown to be a
possible attack.

**Evidence.** Each field's tampering is refused (`BadSignature`) in the fixture tests, the attack lab and
the [campaign](runs/campaign.json).

## 5. InvoiceDeskV3: invoice numbers per vendor; late invoices settled by the company

**Considered.** Keeping V2, whose recorded runs are evidence, and documenting its limits.

**Decision.** Keep V2 deployed and checked, and use V3 for new desks (`desk.mjs setup`), with
`desk.mjs upgrade` to move a company. V3 keys `paid[payer][vendor][id]`, lets the payer settle an
overdue invoice in person (agents stay bound by the due date), refuses zero amounts, and checks the
vendor's balance rose by exactly the invoiced amount. The signed format is V2's, so vendor tools are
unchanged.

**Why.** A buyer's review found both of V2's gaps routine in accounts payable: vendors reuse plain
invoice numbers, and invoices go overdue. Redeploying in place would have voided the recorded evidence.

**Evidence.** [`runs/own-company-v3/`](runs/own-company-v3/); mutants caught, V3: 18 of 18; 8 properties
proved with Halmos ([`runs/halmos.txt`](runs/halmos.txt)).

## 6. Treasury as the bank coin, a small ERC-20 float

**Decision.** The company keeps most fUSD as the Cosmos bank coin, and only a float as ERC-20 for the desk
to pull (`desk.mjs treasury`).

**Why.** An open EVM window is the one place a classical key acts alone. Window or not, the bank coin
moves only with an ML-DSA-87 signature (`MsgConvertERC20`/`MsgConvertCoin` are hybrid-signed Cosmos
messages). So the worst a quantum attacker inside a company window could reach is the float.

**Evidence.** [`runs/probes/company-window.json`](runs/probes/company-window.json): inside the company's own
window, its classical key could not move fUSD, QOR or the treasury.

## 7. Every window names one target

**Decision.** Every EVM window the company or the agent account opens lists its single target
(`allowed_targets`). A contract creation gets its own one-transaction window.

**Why.** A window without targets admits any call within its caps. An independent review found the
company's first windows had none.

## 8. The agent's key stays classical (ed25519), and InvoiceDeskV4 makes it insufficient

**Decision.** We accept the classical relaying key, and from InvoiceDeskV4 we require the agent's own
ML-DSA-87 signature on every agent payment. It covers the desk, the payer, the agent, the vendor, the token,
the amount and the invoice id. The desk checks it against the key of a signer account the company names
(`setAgentSigner`). V3 desks stay as recorded; new desks and `desk.mjs upgrade` are V4.

**Why.** QoreChain authenticators accept only ed25519 or secp256k1 keys today
(`AuthenticatorScheme` in `@qorechain/sdk`), and a quantum computer could derive such a key from its
public key on chain. With V4, that key alone gets `BadAgentSignature` (live:
[`runs/probes/v4-agent-sig.json`](runs/probes/v4-agent-sig.json)).

**What V4 does and does not stop.** It stops a key *derived* from the agent's public key, the
quantum attack: without the signer's ML-DSA-87 secret key, the derived ed25519 key pays nothing. Since
2026-11-26 it also stops a thief of the agent's host alone: the live agent runs as three GitHub Actions jobs,
and only the signer's job, in its own GitHub Environment (`agent-signer`), holds the signer's key; the agent's
jobs never do ([`.github/workflows/live.yml`](.github/workflows/live.yml), rehearsed with separate key folders:
[`runs/probes/live-split-rehearsal.json`](runs/probes/live-split-rehearsal.json)). What it does not stop: a thief
of both hosts, or of the repository's settings (anyone who can edit the workflow can reach both secrets; an
Environment with required reviewers would close that too). The signer is a second key, not a second
judge: the desk still decides. But since 2026-11-25 it checks one thing before it signs (next paragraph).

**Known limits of the agent's signature.** `agentMessage(payer, agent, token, vendor, amount, id)` takes
`token, vendor` in that order but encodes `vendor, token`: call the view, or use `agentMessageV4` in
`lib/invoices.mjs`, rather than re-encoding by hand. The signature has no expiry of its own. It binds one
unpaid invoice, so it is spent when that invoice is paid, and the company voids every outstanding one by
naming another signer (`setAgentSigner`; `desk.mjs signer rotate` does it, kept in
[`runs/own-company-v4/signer-rotate.log`](runs/own-company-v4/signer-rotate.log)).

What we had not drawn from that: a signature sent with a payment the desk *refused* is not spent, and it is
public. A fifth review sent two of ours again as the agent (dry runs) and both would have paid: the
compromised run's `OverDailyLimit` refusal (the next day had room) and the campaign's signed control. So,
on 2026-11-25:
- the three such invoices found were settled by the company in person, so they answer `AlreadyPaid`;
- the signer signs only a payment the desk would make right then, or one it can never make (a vendor
  signature that does not verify, already paid, zero, native QOR, past due): `lib/agent.mjs` `signerMay`.
  It asks without making a signature, by a dry run of the company's own `pay` plus the agent-only rules
  read from the desk, since an `eth_call` would hand the signature to the RPC node;
- `npm run verify` collects every agent signature ever made public (relayed calldata, EVM-lane calldata,
  records in this repository) and sends each again as the agent: none would pay
  ([`runs/signature-sweep.json`](runs/signature-sweep.json)).

The compromised run is the exception by design: its attacker holds the signer, so nothing checks what it
signs, and it leaves such signatures behind. The answer to that is to rotate the signer afterwards.
We did not deploy a V5 with an expiry in the agent's message six days before the deadline. The signer's
check and the rotation close the same hole without moving the live desk.

## 9. Show, don't claim: everything is re-checked from the chain

**Decision.** Every number in the documents comes from `npm run verify` (read-only, no keys), which CI
runs daily. A test fails `npm test` if a document states a count its source no longer gives.

**Why.** An AI built most of this project. Its output is checked, not trusted
([AI_USAGE.md](AI_USAGE.md#checking-the-ai-not-trusting-it)).

## 10. The live agent's key in GitHub Secrets, on purpose

**Decision.** The agent runs daily in GitHub Actions (scheduled; [where each day ran](runs/live/README.md#where-each-day-ran)), with its key, the relayer's key and
the test vendor's key as repository secrets, and a decider that obeys every email. The agent signer's
ML-DSA-87 key (InvoiceDeskV4) is not among them: it is a secret of the `agent-signer` Environment, used
only by the job that signs.

**Why.** It is the design's claim, made live: where the key could leak, the worst case is still bounded.
The agent account's own key, which links and revokes the agent's key, is not in CI. The agent
acts with only its account's address. The vendor's key is there too, so the job can send itself an
invoice each day: a leak of the secrets is therefore also a stolen approved-vendor key, bounded the same
way (genuine-looking invoices to that vendor's own address, within 10 fUSD a payment and 25 a day).

## 11. No MetaMask in the Desk Console

**Considered.** A classic dApp: connect MetaMask, deploy and operate a desk from the browser.

**Decision.** The console reads any desk with no wallet. To act, it talks to `desk.mjs serve` on
127.0.0.1, which signs with the company's hybrid keys. The keys never leave the machine.

**Why.** On qorechain-diana an ordinary EVM wallet cannot send anything: *"has no usable registered
post-quantum key; the EVM lane requires one, like every other lane"*
([`runs/probes/no-pq-evm.json`](runs/probes/no-pq-evm.json)). And the testnet's REST API refuses browsers
(no CORS), so a page cannot build Cosmos transactions by itself.

## 12. A public test vendor whose ML-DSA-87 secret key is published

**Decision.** For the console, a vendor whose ML-DSA-87 key is registered on chain and whose secret key
is published, so any browser can sign invoices as it.

**Why.** It lets anyone see a real ML-DSA-87 invoice signed in a page and paid on chain, with no
vendor-side setup. A desk pays a vendor only if that desk's owner approves it, so it is harmless to every
desk that does not approve it. **An owner who approves it lets anyone bill that desk**, up to its limits:
approve it only on a desk you use to try the console. It was approved on the live V4 desk for the first
compromised-agent run on 2026-11-25 and removed afterwards
([0x5e93ddba…](https://explore.qore.network/tx/0x5e93ddbaab92e179860db4195b21d9128d7088ed5606330d8810b8d49419dbd3));
that run is redone without it on 2026-11-26 (the desk's daily limit was spent on 2026-11-25).
