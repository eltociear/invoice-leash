# Is Invoice Leash ready for a quantum computer?

**Assumption:** a large quantum computer exists. Shor's algorithm breaks every elliptic-curve key
(secp256k1, ed25519, X25519). Grover's algorithm halves the strength of hashes and symmetric
ciphers. What still holds?

**Short answer:** the invoices, the limits and the company's treasury stay safe. Three parts are
classical, and each is bounded:
- the agent's ed25519 key. **On an InvoiceDeskV4 it pays nothing its signer did not sign**: every agent
  payment also needs the agent's own ML-DSA-87 signature over that exact invoice, checked on chain (live: the classical key alone was refused with
  `BadAgentSignature`, then the same invoice with the signature was paid,
  [`runs/probes/v4-agent-sig.json`](runs/probes/v4-agent-sig.json)). On V2/V3 desks it is bounded like a
  stolen key. V4 stops a *derived* key, and a stolen agent host alone, since the signer runs on its own host (see below);
- an EVM window while it is open: one target, a transaction count, a value cap, an expiry. The worst
  case is a company window whose single slot an attacker wins in a race. That gets one call to one
  contract, and never the treasury, which is held as a bank coin;
- a compromised MCP host, which can read sealed invoices.

**Check it yourself:** [Shor's gift](#shors-gift-check-it-yourself) publishes the classical private key of
an account. Take its QOR if you can.

Below: our drill on the live testnet, the windows, and every piece of cryptography in the system.

## Shor's gift: check it yourself

A drill we ran ourselves proves less than one you can run. [`scripts/qday-public.mjs`](scripts/qday-public.mjs)
made an account that holds about 5 QOR and registered its ML-DSA-87 key. Then we published its
**secp256k1 private key** ([`runs/qday-public.json`](runs/qday-public.json)), as if a quantum computer had
already broken it:

- account `qor1ven5euj4fcu30euzz28a90wfw3qshsy58tc8ah` / `0x66674cf2554e3917e782128fd2bdc974410bc094`
- secp256k1 private key `0x3c2292aa10562dceb48dd9d74de999b7e093fc0f8eac619690b963c8e3f8085f`

Anyone can sign anything with it. The [attack lab](https://eltociear.github.io/invoice-leash/lab.html#shor)
signs an EVM transaction in your browser and sends it: *no open EVM authorisation window*. A Cosmos
`MsgSend` signed with it gets code 20 (*must include* the ML-DSA-87 signature). `npm run verify` checks
every day that the QOR is still there and that the account has executed exactly one transaction, its
own key registration ([`4E09315A…`](https://explore.qore.network/tx/4E09315A67FAEF62F51E20CF2ADBB79F96F763C257C7BCBE50EBABA0F451B13E)),
whoever has tried since.

## Our own Q-Day drill

[`scripts/qday-drill.mjs`](scripts/qday-drill.mjs) plays the attacker after Q-Day. It holds the
**secp256k1 keys of four accounts** (company, agent account, relayer, a vendor) and signs with those
keys alone (`signMode: "classical"`), with no ML-DSA-87 key. It sent 16 attacks to `qorechain-diana`:

| Account | Attack, classical key only | The chain's answer |
|---|---|---|
| company | `MsgSend` 1 QOR to the attacker | code 20: *has a registered PQC key and must include* an ML-DSA-87 signature |
| company | EVM: send QOR; `fUSD.transfer`; `fUSD.approve(attacker, max)` | *no open EVM authorisation window* |
| company | EVM: `approveVendor(attacker)`, `setLimit(…, 10^12)`, `setAgent(attacker)` | *no open EVM authorisation window* |
| company | open an EVM window, to then use the classical key inside it | code 20: must include an ML-DSA-87 signature |
| agent account | open an EVM window | code 20 |
| agent account | link the attacker's own key, no limits | code 20 |
| agent account | replace its ML-KEM-1024 key with the attacker's, to read future sealed invoices | code 234: KEM key messages need the PQC key |
| agent account | EVM: send its QOR to the attacker | *no open EVM authorisation window* |
| relayer | `MsgSend` to the attacker | code 20 |
| vendor (Hostline) | EVM: its fUSD to the attacker | *no open EVM authorisation window* |
| vendor (Hostline) | rotate its ML-DSA-87 key to the attacker's (`MsgRotatePQCKey`, the new key's signature valid), to then sign invoices as Hostline | code 20: must include an ML-DSA-87 signature |
| vendor (Hostline) | re-register Hostline with the attacker's ML-DSA-87 key (`MsgRegisterPQCKey`, valid proof of possession) | code 234: *register and migrate need its hybrid signature* |

**16 of 16 refused.** The control, the same kind of request signed hybrid (ML-DSA-87 + secp256k1) by
the real company, went through ([90677647…](https://explore.qore.network/tx/90677647014606987D75A155D03B255D4BA2D57C7762A4F69E39DEB27C643477)).

The refusals happen before a block includes the transaction, so there is no transaction hash to open.
Instead, [`runs/qday-drill.json`](runs/qday-drill.json) records the chain's messages, and
`npm run verify` checks every state change the drill attempted, against the live chain:
- no attacker key is linked to the agent account;
- the agent's ML-KEM key is still the one it registered;
- the attacker has no fUSD allowance from the company;
- the attacker is not an approved vendor and not an agent;
- Hostline's ML-DSA-87 key on chain is not the attacker's, and Hostline is still an approved vendor.

The last two attacks matter most. Invoices are only as strong as the vendor's registered ML-DSA-87
key. If a broken classical key could replace that key, a quantum attacker could sign invoices as any
vendor. The chain refuses both ways of replacing it without the current ML-DSA-87 key.

### Inside an open window

An open EVM window is the one place a classical key acts alone.
[`scripts/probe-window-caps.mjs`](scripts/probe-window-caps.mjs) checks its caps against the agent
account's classical key ([`runs/probes/window-caps.json`](runs/probes/window-caps.json)):
- a window for 1 transaction: the first call executed, the second was refused (*window exhausted*,
  0 transactions left);
- a window for 0.02 QOR: a call carrying 0.05 QOR was refused (*needs 62750 uqor*, 20000 left).

Together with the target list ([`runs/probes/window.json`](runs/probes/window.json): fUSD and
Mallory refused), the window's count, value, target and expiry all hold.

### The company's own windows

The company opens a window for a single action, such as paying an over-limit invoice in person or the
kill switch. Each one names one target and admits exactly the transactions of that action: one for an
approval, a payment in person or a freeze; two for the demo's kill switch (off, then on again); more only
for setup and `upgrade`, which run once (`scoped(...)` in
[`leash.mjs`](leash.mjs)). [`scripts/probe-company-window.mjs`](scripts/probe-company-window.mjs) opened one
the way `approve-v2` does (InvoiceDeskV2 only, 1 transaction). While it was open, the company's classical
key alone tried three things ([`runs/probes/company-window.json`](runs/probes/company-window.json)):

| Attack, company's classical key, window open | The chain's answer |
|---|---|
| `fUSD.transfer(Mallory, 1)` | refused: the window does not list fUSD |
| 1 QOR to Mallory | refused: the window does not list Mallory |
| `MsgSend` of the whole treasury (the bank-coin fUSD, 1,108 fUSD) | code 20: must include an ML-DSA-87 signature |

**The treasury and the float.** The desk pulls fUSD from the company's ERC-20 balance, and an ERC-20
balance is what a window can reach. So only a float stays there (about 400 fUSD, more than a day of
agent payments). The rest is the bank coin, which moves only through hybrid-signed Cosmos messages
(`MsgConvertERC20` / `MsgConvertCoin`, `node leash.mjs treasury-v2`). The float is refilled the same way,
with no window.

**What is left.** A quantum attacker who watches the chain could try to win the race for the one slot
of a window the company has just opened. With a desk window, that buys one call to the desk, such as
`approveVendor(attacker)`. Even then, the attacker's invoices are paid only within the agent's limits
(250 fUSD a day). The company notices at once, because its own transaction is refused (the slot is
used). The allowance window (target fUSD) is the widest: one `fUSD.transfer` of the float. The
allowance is set rarely, so keep the float small when you open it.

Setup and `upgrade` open windows with several slots, once. An attacker who won several of them could
chain calls, say `approveVendor(attacker)` then a higher `setLimit`, and with the agent's (classical)
key have its own invoices paid. In every case the bound is the same: **the ERC-20 float**, because the
desk can only pull from it and the treasury is a bank coin no window reaches. That is why the float is
kept small.

### No classical-only lane at all

An ordinary EVM wallet, a fresh secp256k1 key funded with 1 QOR and no post-quantum key, cannot send
anything on `qorechain-diana`: *"account … has no usable registered post-quantum key; the EVM lane
requires one, like every other lane"* ([`runs/probes/no-pq-evm.json`](runs/probes/no-pq-evm.json)). So a
quantum attacker who derives a key nobody registered gets nowhere either, and that is also why the
[Desk Console](https://eltociear.github.io/invoice-leash/app.html) signs through your own hybrid keys, not
a MetaMask-style wallet.

## Every piece of cryptography, and what a quantum computer does to it

| Where | Algorithm | Quantum status | If broken, the attacker gets | Evidence |
|---|---|---|---|---|
| Company, agent-account, relayer and vendor **transactions** | hybrid: secp256k1 + **ML-DSA-87** (FIPS 204, level 5); the chain requires the ML-DSA-87 layer once a PQC key is registered | ML-DSA-87: safe. secp256k1: broken, but **alone it is refused** | nothing | drill (code 20); every recorded tx shows `pqc_hybrid_verify: verified` |
| **EVM transactions** (secp256k1 only) | accepted only inside an EVM window, which only an ML-DSA-87-signed transaction can open | breakable | only what an *open* window admits: its tx count, value cap, expiry and (for the agent account) its one target, the desk | drill ("no open EVM authorisation window"); [`runs/probes/window.json`](runs/probes/window.json) (target), [`runs/probes/window-caps.json`](runs/probes/window-caps.json) (count, value) |
| **Vendor invoices** | **ML-DSA-87**, verified on chain by `pqcVerify` (`0x…0a01`) against the key in `pqcKeyStatus` (`0x…0a02`), proof of possession required | safe | — | demo inbox, verify §4/§9, 152 Foundry tests, 17 invariants |
| **Company instructions** to the agent | QoreSign message-signing-v1: secp256k1 (ADR-36) + **ML-DSA-87** over `qorechain-msg-v1\|chain\|text` | ML-DSA-87 half: safe | a valid classical half is not enough: the Q-Day forgery is refused | [`runs/messages.json`](runs/messages.json), the lab |
| **Sealed invoices** | **ML-KEM-1024** (FIPS 203, level 5), `mlkem` mode (no X25519), HKDF with SHA3-256, AES-256-GCM | safe against "harvest now, decrypt later"; AES-256 keeps about 128-bit strength under Grover | — | [`runs/sealed.json`](runs/sealed.json) |
| **The agent's key**, on InvoiceDeskV4 | **ed25519** to relay (authenticators accept only ed25519 / secp256k1 today) **plus the agent signer's ML-DSA-87** on every payment | the ed25519 half: broken; the ML-DSA-87 half: safe | nothing from a derived ed25519 key alone (`BadAgentSignature`), nor from the agent's host alone (the signer runs in its own job). Both hosts stolen: what a stolen agent key gets | [`runs/probes/v4-agent-sig.json`](runs/probes/v4-agent-sig.json), [`runs/probes/window-v4.json`](runs/probes/window-v4.json), the live agent's daily attempt, [985 tampered or missing agent signatures](runs/campaign-v4.json) (all `BadAgentSignature`), Foundry, Halmos |
| **The agent's key**, on V2/V3 desks | **ed25519** | **broken** | exactly what a stolen agent key gets: genuine invoices from approved vendors, within the company's limits; nothing else | the compromised-agent run (16 attempts, 3 genuine paid), probes |
| Hashes: invoice ids, the signed message, EVM | Keccak-256, SHA3-256 | Grover: about 128-bit preimage strength; collisions remain out of reach | — | — |
| Contract admin (`approveVendor`, `setLimit`, `setAgent`) | `msg.sender` = the company, reachable only through an ML-DSA-87-opened window, scoped to the desk | while no window is open: safe. While one is: at most the window's one slot, if the attacker wins the race | one admin call, bounded by the agent's limits; the company's own call then fails | drill (three EVM admin calls refused), [`runs/probes/company-window.json`](runs/probes/company-window.json) |
| `npm run verify`, the lab, the site | reads only; ML-DSA-87 verified in the browser with noble-post-quantum | no secrets | — | — |
| TLS to the public RPC endpoints | X25519MLKEM768 hybrid key exchange, ECDSA certificates (from the CBOM) | key exchange: post-quantum hybrid; the certificates are classical (the operator's, not ours) | reads only: a forged read cannot move money | [`cbom/`](cbom/invoice-leash.cbom.json) |
| QoreChain consensus | validators' Ed25519 keys (from the CBOM) | classical | out of this project's scope: chain-level | CBOM |

## What remains classical, and why that is acceptable

1. **The agent's ed25519 key.** QoreChain authenticators accept only ed25519 or secp256k1 today, so the
   key that relays the agent's requests stays classical. InvoiceDeskV4 makes it insufficient: the desk
   also requires the agent's own ML-DSA-87 signature over this desk, this payer, this agent and this
   exact invoice, verified with the precompile against the key of the signer the company named
   (`setAgentSigner`). After Q-Day, deriving the ed25519 key from its public key pays nothing. The live
   agent's desk is a V4 and its daily run includes that attempt. On V2/V3 desks the key is bounded like
   a stolen key. When authenticators accept ML-DSA-87, the relaying key can be post-quantum too.

   **What V4 does and does not stop.** It stops a key *derived* from the agent's public key, the
   quantum attack: without the signer's ML-DSA-87 secret key, the derived ed25519 key pays nothing. Since
   2026-11-26 it also stops a thief of the agent's host alone: the live agent runs as three GitHub Actions jobs,
   and only the signer's job, in its own GitHub Environment (`agent-signer`), holds the signer's key; the agent's
   jobs never do ([`.github/workflows/live.yml`](.github/workflows/live.yml), rehearsed with separate key folders:
   [`runs/probes/live-split-rehearsal.json`](runs/probes/live-split-rehearsal.json)). What it does not stop: a thief
   of both hosts, or of the repository's settings (anyone who can edit the workflow can reach both secrets; an
   Environment with required reviewers would close that too). The signer is a second key, not a second
   judge, but it does check one thing before it signs: that the desk would pay this request right then
   (or can never pay it). The reason: an agent signature has no expiry of its own. It binds one invoice
   and holds until that invoice is paid or past due, and it is public (in the relaying transaction). One
   made for a payment the desk refused, over today's limit say, could be sent again on a later day by the
   classical key alone. A fifth review found exactly that: the compromised run's `OverDailyLimit`
   refusal and the campaign's signed control would both have paid. Both were then settled in person,
   the signer got its check (`lib/agent.mjs` `signerMay`, asked without making a signature), and
   `npm run verify` now sends every agent signature ever made public again as the classical key alone
   ([`runs/signature-sweep.json`](runs/signature-sweep.json): 57, none would pay). The rest could pay only if the company
   itself first approved that vendor or raised the limit. To void every signature a signer ever made, the
   company names a new one: `desk.mjs signer rotate`, done on the third company
   ([`runs/own-company-v4/signer-rotate.log`](runs/own-company-v4/signer-rotate.log)). A V5 would put an expiry in the
   agent's message itself.
2. **An open EVM window.** A quantum attacker with a classical key can act inside a window while it is
   open, within its caps. Every window names one target. The agent account's window is 300 blocks, at
   most 3 transactions and 0.4 QOR, to the desk. The company's windows admit one action and close in
   the same command. The treasury is a bank coin that no window reaches (above).
3. **The MCP host.** It holds the agent's ed25519 key and its ML-KEM seed. Losing the host means a
   compromised agent (bounded, see 1) and the ability to read sealed invoices addressed to it. That is a
   loss of confidentiality, not of money.

## Migration: what changes when the threat model does

| Event | What to do | Already tested |
|---|---|---|
| A vendor's ML-DSA-87 key is rotated or lost (a classical-only rotation is refused: drill) | the desk reads the key at payment time, so invoices signed with the old key stop verifying | Foundry: rotated key refused (v1 and v2) |
| The agent's key leaks | `setAgent(agent, false)` (one company tx), or revoke on chain | kill switch, live; v1 revoke, live |
| QoreChain accepts post-quantum authenticators | link an ML-DSA-87 agent key instead of ed25519 | — (the chain does not support it yet) |
| The agent's KEM key must change | register a new one (needs the account's ML-DSA-87 signature, as the drill shows) | drill: the classical-only replacement refused |
