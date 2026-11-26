# QoreChain, measured: notes for builders

What building Invoice Leash taught us about `qorechain-diana`, each with the transaction or record that
shows it. We measured these on the testnet between 2026-11-20 and 2026-11-25. They are observations, not
documentation: if the chain changes, the records stay as evidence of what it did then.

## Accounts and keys

**1. A spending rule bounds amounts, not destinations.** A linked key whose rule allowed one EVM call
(`InvoiceDesk.pay`) still sent 0.01 QOR to a fresh address with no call data, and moved a listed ERC-20
with a plain `transfer`. The rule's denom and amount limits held; its call list did not restrict where
value went.
- Evidence: [779FAF6E…](https://explore.qore.network/tx/779FAF6E8871B3FFF1D0D2D129AC904529E78E5198718C1DD630676E05AD4CEC), [`runs/probes/probes.json`](runs/probes/probes.json).
- What to do: give an agent its own account holding nothing the rule lists. That account's money cannot
  move at all, and the funds can only move through a contract that pulls them.

**2. There is no classical-only lane.** An ordinary EVM wallet with no registered post-quantum key cannot
send anything: *"has no usable registered post-quantum key; the EVM lane requires one, like every other
lane"*. MetaMask alone cannot use the chain.
- Evidence: [`runs/probes/no-pq-evm.json`](runs/probes/no-pq-evm.json).
- What to do: plan for keys that live where an ML-DSA-87 signer is. Invoice Leash's web console signs
  through a local process (`desk.mjs serve`).

**3. Once an account registers its ML-DSA-87 key, its classical key alone is refused**, before any block:
*"hybrid PQC signature required"* (code 20). Replacing that PQC key, or a KEM key, also needs the hybrid
signature (code 234).
- Evidence: [`runs/qday-drill.json`](runs/qday-drill.json).

**4. EVM windows are enforced as stated.** The window's transaction count, value+fee cap, block expiry
and `allowed_targets` all held. This includes the account owner's own classical key inside the window.
Only a hybrid-signed `MsgOpenEVMWindow` opens one.
- Evidence: [`runs/probes/window-caps.json`](runs/probes/window-caps.json),
  [`runs/probes/window-v4.json`](runs/probes/window-v4.json), [`runs/probes/company-window.json`](runs/probes/company-window.json).

## Relayed EVM calls (`MsgExecuteEVM` through an authenticator)

**5. They leave no log that `eth_getLogs` returns.** The block holds no EVM transaction for them, so an
indexer that reads contract events misses every agent payment.
- Evidence: [D7D404F7…](https://explore.qore.network/tx/D7D404F7155E96952746F75A0D3FD83423CA8C5FF37D4CDD01DFE70CA977AFD4).
- What to do: read the relayer's Cosmos transactions (`message.sender`) and confirm against contract
  state. `desk.mjs export` does both.
- Which transactions name the agent's account: a **refused** relay names it in its
  `abstractaccount_execution_failed` event (attribute `account`), so
  `query=abstractaccount_execution_failed.account='qor1…'` finds every refused call for that account, whoever
  relayed it ([6E88AC52…](https://explore.qore.network/tx/6E88AC529A07BBAFE53CF695D5CF7A86C813C31376A476D6160E5675C5572A42)).
  A **successful** relay names it in no event; only the message body holds it
  ([2ED77180…](https://explore.qore.network/tx/2ED771805A73B521EA2248A694723710EDA7072F21E9AC58C0103F672B3F3004)).
  To find every call made for an account, you must know its relayers. (`scripts/signature-sweep.mjs` uses both
  queries.)

**6. The relaying transaction must provision at least the gas the linked key signed.** Otherwise it is
refused before the spending rule is asked: *"the transaction provisions 808336 gas for the call, less than
the signed gas_limit 1000000"*. The transaction fails (code 10), unlike a rule's or a contract's refusal.
Its message also says *"authenticator not permitted"*, which reads like a rule refusal but is not one.
- Evidence: [`runs/probes/relay-gas-mismatch.json`](runs/probes/relay-gas-mismatch.json).
- What to do: use one (signed gas, relay gas) pair for every request.

**7. A refused call is a successful transaction, whether the spending rule or the contract refused it.** The tx has `code 0`, an
`abstractaccount_execution_failed` event, and *"execution reverted"*. The contract's revert bytes are in
`tx_response.data`: field 2 of `MsgExecuteEVMResponse`, inside `TxMsgData`. So the exact error (for
example `BadSignature`) can be read back from the chain later.
- Evidence: `npm run verify` decodes them for every refused V4 payment ([`scripts/verify.mjs`](scripts/verify.mjs)).
- What to do: check the event, not the code. Decode `data` for the contract's reason. Only a malformed relay (note 6) fails as a transaction.

**8. The fee is charged on the gas asked for, whether the call succeeds or is refused** (0.15 uqor per
unit). A hostile agent can therefore spend its relayer's fees on refused requests, and nothing else.
- Evidence: [EVIDENCE.md, what it costs](EVIDENCE.md#what-it-costs).
- What to do: keep the relayer small, and ask for no more gas than the call needs.

## Tokens and endpoints

**9. One ERC-20, two spellings.** The bank module names the coin `erc20:0x…` (colon). Spending rules and
the authenticator's messages name it `erc20/0x…` (slash). A `MsgSend` with the slash spelling is a
different, empty denom, refused as *"insufficient funds"*.
- Evidence: [`runs/probes/denom-notation.json`](runs/probes/denom-notation.json).

**10. A web page can use the EVM RPC, not REST.** `evm-testnet.qore.host` answers with
`access-control-allow-origin: *`. `api-testnet.qore.host` sends no CORS header and answers a preflight
with 501. So a page can read and dry-run contracts, but cannot query REST or broadcast Cosmos
transactions.
- Evidence: [`runs/probes/cors.json`](runs/probes/cors.json).

## The PQC precompiles from Solidity

**11. `0x…0a02` (key status) and `0x…0a01` (ML-DSA-87 verify) work from a contract.**
- `0x…0a02` returns the registered key, its algorithm and whether possession was proven.
- `0x…0a01` verifies a 4,627-byte ML-DSA-87 signature against it.
- InvoiceDeskV4 and V5 make two such verifications per agent payment: the vendor's invoice and the agent's
  own signature (on V5 over a 256-byte message that holds the invoice's digest and a deadline).
- Local EVMs have no such precompile. Invoice Leash tests against a stand-in that answers only for real
  ML-DSA-87 tuples checked off chain ([`test/fixtures/`](test/fixtures/)).
- Evidence: every V4 payment and refusal; the [attack lab](https://eltociear.github.io/invoice-leash/lab.html)
  runs the precompile for real through `eth_call`.
