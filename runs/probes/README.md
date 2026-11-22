# Probes: what a QoreChain spending-rule-bound key can move

Measured on `qorechain-diana` on 2026-11-22 with the scripts in `scripts/probe-*.mjs`. Each probe is
one `MsgExecuteEVM` by the agent's ed25519 key, relayed by the gas wallet. The list, with the tx of
each and what it taught, is [`probes.json`](probes.json); `npm run verify` §8 re-reads every tx.
The README's "What we found" section explains the consequence for the design.
