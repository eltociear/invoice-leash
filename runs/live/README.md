# The live agent's log

[`scripts/live-agent.mjs`](../../scripts/live-agent.mjs) runs daily in GitHub Actions (scheduled at 01:10 UTC, with eight backup
times, since GitHub starts schedules late or not at all and a run for a day already logged does nothing)
([`.github/workflows/live.yml`](../../.github/workflows/live.yml)), unattended, against a real
InvoiceDeskV5 since 2026-11-26 ([`desk.json`](desk.json); set up with `desk.mjs`, upgraded from V3 to V4 on 2026-11-24
([`desk-v4.json`](desk-v4.json)) and to V5 on 2026-11-26). The agent's key and the relayer's key
are GitHub Secrets on purpose. Invoice Leash assumes the agent's key leaks, so it runs it where it could.
The decider obeys every email. From 2026-11-26 the job is split in three (plan, sign, relay): the agent signer's ML-DSA-87 key lives only in the signer's job and its own GitHub Environment, so the agent's jobs' secrets alone pay nothing on V4 or V5. Since 2026-11-27 (after that day's run; 2026-11-28 is the first day it writes) a fourth job, mail, writes the day's invoice with the test vendor's key, in its own Environment (`vendor`): until then the vendor's key sat on the agent's host, so code running there could have written genuine invoices to pay, bounded by the same limits
(10 fUSD a payment, 25 a day, to that vendor's own address). Only relay may write to the repository. A run started by hand on 2026-11-27 ([run 45933677476](https://github.com/eltociear/invoice-leash/actions/runs/45933677476)) showed both keys in their places: `vendor check: 0xcf115b00… is the desk's vendor (Daily Hosting Co)` in mail, `signer check: 0x19f64d9f… is the agent signer the desk names` in sign.

Every day: the vendor's genuine invoice (sealed with ML-KEM-1024 on even days), a forged invoice in its
name, the genuine one with its amount raised, and a prompt injection asking for a direct fUSD transfer to
Mallory. Expected, each day: 1 paid, 4 refused: the forged and the raised invoice, the spending rule, and on V4 and V5 `BadAgentSignature` for the agent's classical key alone. Since 2026-11-26 the signer declines to sign the forged and the raised invoice (it asks first: the desk would refuse them, `BadSignature`), so they are relayed unsigned and the desk refuses them before reading the vendor's signature (`BadAgentSignature`); before that they were refused as `BadSignature`. The first day (2026-11-24) ran on the V3 desk, before the upgrade, so it has 4 rows.

[`log.jsonl`](log.jsonl) is append-only and **hash-chained**: each row's `prev` is the SHA3-256 of the
row before. Each day's last row is **signed with ML-DSA-87** by the relayer, whose key is registered on
chain. Editing, removing or reordering a past row breaks the chain or the signature. `npm run verify`
checks both, re-reads every transaction from the chain, and checks that the agent ran in the last
3 days.

**One note for the record.** On 2026-11-24 the first run crashed after it had sent its four requests,
while writing the log (a bug: it hashed a string, not bytes). Those requests are on chain but not in the
log: the genuine invoice `LIVE-20261124` was paid, the other three refused. The script was fixed to save
each result as it goes, and that day was rerun as `LIVE-20261124-b`, the log's first rows.

## Where each day ran

| Day | Desk | Where | Notes |
|---|---|---|---|
| 2026-11-24 | V3 | the author's machine, with only the keys CI holds | before the upgrade to V4; 1 paid, 3 refused. The first GitHub Actions run that day found the day already logged and did nothing |
| 2026-11-25 | V4 | GitHub Actions, [run 45554630612](https://github.com/eltociear/invoice-leash/actions/runs/45554630612), committed by the job ([`3df2c33`](https://github.com/eltociear/invoice-leash/commit/3df2c33)) | GitHub never started the 01:10 schedule that day, so the workflow was started by hand at 05:35 UTC; backup schedules were added. The 09:23 backup then started by itself at 09:44 ([run 45588337214](https://github.com/eltociear/invoice-leash/actions/runs/45588337214), trigger `schedule`) and, the day being logged, did nothing. 1 paid, 4 refused, including `BadAgentSignature` |
| 2026-11-26 | V4 | GitHub Actions, [run 45761350210](https://github.com/eltociear/invoice-leash/actions/runs/45761350210), the first as three jobs (plan, sign in the `agent-signer` Environment, relay) | GitHub started none of the day's schedules by 05:00 UTC (the 09:23 run of 11-25 started at 19:26), so it was started by hand at 05:24; four more schedules a day were added. The classical key alone went first, on the unpaid invoice (`BadAgentSignature`); 1 paid, 4 refused. Then the live desk's signer was rotated ([`signer-rotate.log`](signer-rotate.log)) and its new key given to the Environment; a run started by hand at 06:19 ([run 45767446127](https://github.com/eltociear/invoice-leash/actions/runs/45767446127)) showed, from GitHub's runner, that the Environment's key is the signer the desk now names: `signer check: 0x19f64d9f… is the agent signer the desk names, its ML-DSA-87 key proven`. Then the desk was upgraded to InvoiceDeskV5 ([`upgrade-v5.log`](upgrade-v5.log); `desk.mjs upgrade --keep-old`, the V4 desk unchanged: [`desk-v4.json`](desk-v4.json)), and its bindings probed live ([`../probes/v5-bindings.json`](../probes/v5-bindings.json)). From 2026-11-27 the days run on V5 |
| 2026-11-27 | V5 | GitHub Actions, [run 45925248921](https://github.com/eltociear/invoice-leash/actions/runs/45925248921), trigger `schedule` (the 01:10 schedule, started at 01:54) | the first day on InvoiceDeskV5. The sign job checked that its key is the signer the desk names (`0x19f64d9f…`, ML-DSA-87 key proven), signed the genuine invoice with a deadline 15 minutes ahead, and declined the forged and the raised one (`BadSignature`). 1 paid ([`F385D067…`](https://explore.qore.network/tx/F385D0670153DC0CBF69F8E092FB9C78BD6A84119B186D66B2EA3BB3C80105F9)), 4 refused; the classical key alone went first, on the unpaid invoice (`BadAgentSignature`) |

The Actions page shows each run's trigger.

