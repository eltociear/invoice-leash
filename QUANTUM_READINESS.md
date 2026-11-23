# Is Invoice Leash ready for a quantum computer?

**Assumption:** a large quantum computer exists. Shor's algorithm breaks every elliptic-curve key
(secp256k1, ed25519, X25519). Grover's algorithm halves the strength of hashes and symmetric
ciphers. What still holds?

**Short answer:** the money, the limits and the invoices stay safe. Three parts are classical, and each
is bounded or confidential-only, never a path to the company's money:
- the agent's ed25519 key, bounded like a stolen key;
- an EVM window while it is open, bounded by its own caps;
- a compromised MCP host, which can read sealed invoices.

Below is every piece of cryptography in the system, then a drill we ran on the live testnet to test the
assumption.

## Our own Q-Day drill

[`scripts/qday-drill.mjs`](scripts/qday-drill.mjs) plays the attacker after Q-Day. It holds the
**secp256k1 key of every account** (company, agent account, relayer, a vendor) and signs with those
keys alone (`signMode: "classical"`), with no ML-DSA-87 key. It sent 14 attacks to `qorechain-diana`:

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

**14 of 14 refused.** The control, the same kind of request signed hybrid (ML-DSA-87 + secp256k1) by
the real company, went through ([C88161D6…](https://explore.qore.network/tx/C88161D652DBF86E118BC7B999B7CA24FF7AD8A987333857CB2E93943F9C2AA5)).

The refusals happen before a block includes the transaction, so there is no transaction hash to open.
Instead, [`runs/qday-drill.json`](runs/qday-drill.json) records the chain's messages, and
`npm run verify` checks every state change the drill attempted, against the live chain:
- no attacker key is linked to the agent account;
- the agent's ML-KEM key is still the one it registered;
- the attacker has no fUSD allowance from the company;
- the attacker is not an approved vendor and not an agent.

## Every piece of cryptography, and what a quantum computer does to it

| Where | Algorithm | Quantum status | If broken, the attacker gets | Evidence |
|---|---|---|---|---|
| Company, agent-account, relayer and vendor **transactions** | hybrid: secp256k1 + **ML-DSA-87** (FIPS 204, level 5); the chain requires the ML-DSA-87 layer once a PQC key is registered | ML-DSA-87: safe. secp256k1: broken, but **alone it is refused** | nothing | drill (code 20); every recorded tx shows `pqc_hybrid_verify: verified` |
| **EVM transactions** (secp256k1 only) | accepted only inside an EVM window, which only an ML-DSA-87-signed transaction can open | breakable | only what an *open* window admits: its tx count, value cap, expiry and (for the agent account) its one target, InvoiceDeskV2 | drill ("no open EVM authorisation window"); [`runs/probes/window.json`](runs/probes/window.json) |
| **Vendor invoices** | **ML-DSA-87**, verified on chain by `pqcVerify` (`0x…0a01`) against the key in `pqcKeyStatus` (`0x…0a02`), proof of possession required | safe | — | demo inbox, verify §4/§9, 59 tests, 5 invariants |
| **Company instructions** to the agent | QoreSign message-signing-v1: secp256k1 (ADR-36) + **ML-DSA-87** over `qorechain-msg-v1\|chain\|text` | ML-DSA-87 half: safe | a valid classical half is not enough: the Q-Day forgery is refused | [`runs/messages.json`](runs/messages.json), the lab |
| **Sealed invoices** | **ML-KEM-1024** (FIPS 203, level 5), `mlkem` mode (no X25519), HKDF with SHA3-256, AES-256-GCM | safe against "harvest now, decrypt later"; AES-256 keeps about 128-bit strength under Grover | — | [`runs/sealed.json`](runs/sealed.json) |
| **The agent's key** | **ed25519** (QoreChain authenticators accept only ed25519 / secp256k1 today) | **broken** | exactly what a stolen agent key gets: genuine invoices from approved vendors, within the company's limits; nothing else | the compromised-agent run (16 attempts, 3 genuine paid), probes |
| Hashes: invoice ids, the signed message, EVM | Keccak-256, SHA3-256 | Grover: about 128-bit preimage strength; collisions remain out of reach | — | — |
| Contract admin (`approveVendor`, `setLimit`, `setAgent`) | `msg.sender` = the company, reachable only through an ML-DSA-87-opened window or a hybrid transaction | inherits the account's protection | — | drill (three EVM admin calls refused) |
| `npm run verify`, the lab, the site | reads only; ML-DSA-87 verified in the browser with noble-post-quantum | no secrets | — | — |
| TLS to the public RPC endpoints | X25519MLKEM768 hybrid key exchange, ECDSA certificates (from the CBOM) | key exchange: post-quantum hybrid; the certificates are classical (the operator's, not ours) | reads only: a forged read cannot move money | [`cbom/`](cbom/invoice-leash.cbom.json) |
| QoreChain consensus | validators' Ed25519 keys (from the CBOM) | classical | out of this project's scope: chain-level | CBOM |

## What remains classical, and why that is acceptable

1. **The agent's ed25519 key.** Invoice Leash already treats it as stolen; the whole design is
   about what a thief can do with it. When QoreChain authenticators accept ML-DSA-87, `link-v2`
   changes one argument.
2. **An open EVM window.** A quantum attacker with a classical key can act inside a window while it is
   open. Keep windows short and scoped. The agent account's window is 300 blocks, at most 3
   transactions and 0.4 QOR, to one target. The company opens windows only for a single action and
   closes them in the same command (`approve-v2`, `allowance-v2`).
3. **The MCP host.** It holds the agent's ed25519 key and its ML-KEM seed. Losing the host means a
   compromised agent (bounded, see 1) and the ability to read sealed invoices addressed to it. That is a
   loss of confidentiality, not of money.

## Migration: what changes when the threat model does

| Event | What to do | Already tested |
|---|---|---|
| A vendor's ML-DSA-87 key is rotated or lost | the desk reads the key at payment time, so invoices signed with the old key stop verifying | Foundry: rotated key refused (v1 and v2) |
| The agent's key leaks | `setAgent(agent, false)` (one company tx), or revoke on chain | kill switch, live; v1 revoke, live |
| QoreChain accepts post-quantum authenticators | link an ML-DSA-87 agent key instead of ed25519 | — (the chain does not support it yet) |
| The agent's KEM key must change | register a new one (needs the account's ML-DSA-87 signature, as the drill shows) | drill: the classical-only replacement refused |
