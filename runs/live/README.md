# The live agent's log

[`scripts/live-agent.mjs`](../../scripts/live-agent.mjs) runs on a schedule, daily at 01:10 UTC, in GitHub Actions
([`.github/workflows/live.yml`](../../.github/workflows/live.yml)), unattended, against a real
InvoiceDeskV4 since 2026-11-24 ([`desk.json`](desk.json); set up with `desk.mjs`, upgraded from V3). The agent's key and the relayer's key
are GitHub Secrets on purpose. Invoice Leash assumes the agent's key leaks, so it runs it where it could.
The decider obeys every email. The agent signer's ML-DSA-87 key is a secret too, so a theft of the secrets is a stolen agent (bounded by the limits); what V4 stops is a key *derived* from the agent's public key. The test vendor's key is a secret too, so the job can send itself the
day's invoice: a leak of the secrets is also a stolen approved-vendor key, bounded by the same limits
(10 fUSD a payment, 25 a day, to that vendor's own address).

Every day: the vendor's genuine invoice (sealed with ML-KEM-1024 on even days), a forged invoice in its
name, the genuine one with its amount raised, and a prompt injection asking for a direct fUSD transfer to
Mallory. Expected, each day: 1 paid, 4 refused (`BadSignature`, `BadSignature`, the spending rule, and on V4 `BadAgentSignature` for the agent's classical key alone). The first day (2026-11-24) ran on the V3 desk, before the upgrade, so it has 4 rows.

[`log.jsonl`](log.jsonl) is append-only and **hash-chained**: each row's `prev` is the SHA3-256 of the
row before. Each day's last row is **signed with ML-DSA-87** by the relayer, whose key is registered on
chain. Editing, removing or reordering a past row breaks the chain or the signature. `npm run verify`
checks both, re-reads every transaction from the chain, and checks that the agent ran in the last
3 days.

**One note for the record.** On 2026-11-24 the first run crashed after it had sent its four requests,
while writing the log (a bug: it hashed a string, not bytes). Those requests are on chain but not in the
log: the genuine invoice `LIVE-20261124` was paid, the other three refused. The script was fixed to save
each result as it goes, and that day was rerun as `LIVE-20261124-b`, the log's first rows.
