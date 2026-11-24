# Design decisions

Each decision, what we considered, and the evidence that settled it. Newest last.

## 1. The agent is assumed compromised

**Decision.** The agent's code checks nothing. It has no limit check, no vendor check and no signature
check. Every limit lives on QoreChain or in the contract.

**Why.** A bill-paying agent reads email written by strangers, so prompt injection is a matter of time,
and its key lives on a server. A design that is safe only while the model behaves is not safe.

**Evidence.** A decider that obeys every email made 16 payment attempts and got only the 3 genuine
invoices paid ([README](README.md#the-demo-inbox-v2-fusd)). The live agent runs that decider every day
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

## 8. The agent's key stays classical (ed25519)

**Decision.** We accept it and design for it being stolen.

**Why.** QoreChain authenticators accept only ed25519 or secp256k1 keys today
(`AuthenticatorScheme` in `@qorechain/sdk`). When they accept ML-DSA-87, `link-v2` changes one argument.

## 9. Show, don't claim: everything is re-checked from the chain

**Decision.** Every number in the documents comes from `npm run verify` (read-only, no keys), which CI
runs daily. A test fails `npm test` if a document states a count its source no longer gives.

**Why.** An AI built most of this project. Its output is checked, not trusted
([AI_USAGE.md](AI_USAGE.md#checking-the-ai-not-trusting-it)).

## 10. The live agent's key in GitHub Secrets, on purpose

**Decision.** The agent runs every day in GitHub Actions, with its key and the relayer's key as
repository secrets, and a decider that obeys every email.

**Why.** It is the design's claim, made live: where the key could leak, the worst case is still bounded.
The agent account's own key, which links and revokes the agent's key, is not in CI. The agent
acts with only its account's address.

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
vendor-side setup. It is harmless by construction: a desk pays a vendor only if that desk's owner
approves it.
