# A fourth company, set up from nothing on InvoiceDeskV5

Run on 2026-11-27 by following [GETTING_STARTED.md](../../GETTING_STARTED.md), with fresh keys (`LEASH_HOME`,
`LEASH_VENDOR_HOME`) and nothing reused from the other desks. The company and its vendor were funded the way the
faucet would (15 QOR and 100 fUSD as the bank coin; 1.5 QOR for the vendor:
[74AD92A5…](https://explore.qore.network/tx/74AD92A54DADBAAB8D82159A0CA73A0C82FCD872BBA87F2EFDB9AE40389615EF)).
Keys and mnemonics stay in `~/.config`; nothing secret is in this folder.

| Step | Command | Record |
|---|---|---|
| keys | `desk.mjs init`; `vendor.mjs init` | [`init.log`](init.log), [`vendor-init.log`](vendor-init.log) |
| desk | `desk.mjs setup --per-payment 30 --daily 60 --allowance 200 --float 60 --hours 720` | [`setup.log`](setup.log): in one pass, ML-DSA-87 keys registered, InvoiceDeskV5 deployed at [`0x259482c9…`](https://explore.qore.network/address/0x259482c9e4dD6194f0f5247d73E54DBE7A5AeFaE), agent signer named, agent key linked (one call: the desk's `pay`), KEM key published, float 60 / treasury 40 |
| vendor | `vendor.mjs register`; `desk.mjs vendor add` | [`vendor-register.log`](vendor-register.log), [`vendor-add.log`](vendor-add.log): Lighthouse Analytics, its own ML-DSA-87 key |
| invoices | `vendor.mjs sign …` (one sealed with `--seal-to`, one re-issued `--overdue`, one over the agent's limit); an edited copy; one from Harbor Cloud, a real vendor this company never approved | [`invoices/`](invoices/), [`inbox-add.log`](inbox-add.log) |
| triage | `desk.mjs triage` | [`triage.log`](triage.log): 2 AGENT PAYS, 2 NEEDS A PERSON (over the limit; past due), 2 REJECTED (`BadSignature`, `UnknownVendor`) |
| agent | `desk.mjs run` | [`run.log`](run.log): LA-2001 and the sealed LA-2002 paid, each with the agent signer's ML-DSA-87 signature over the whole invoice and a 15-minute deadline |
| person | `desk.mjs pay 3`, then `pay 2` | [`pay.log`](pay.log): the overdue LA-1990 settled in person; the 45 fUSD LA-2003 first refused with the reason and the fix (`TransferFailed`: float too low), then paid after `desk.mjs treasury 45` ([`treasury.log`](treasury.log)) |
| accounting | `desk.mjs export` | [`payments.csv`](payments.csv): 4 payments, read from the chain |
| final | `desk.mjs triage`, `status` | [`triage-after.log`](triage-after.log), [`status.log`](status.log) |
| console | `desk.mjs serve`, the [Desk Console](https://eltociear.github.io/invoice-leash/app.html) driven in a real browser (`scripts/console-e2e.mjs rotate,triage,run,export`), after two more invoices (LA-2010, the sealed LA-2011) and more test fUSD ([CCBFD0B8…](https://explore.qore.network/tx/CCBFD0B8AF4454A692CF47861C0DC788DEF1E13204F08806CD02D28808E91CF4); `treasury 60`, [`treasury-2.log`](treasury-2.log)) | [`../console-e2e-v5.json`](../console-e2e-v5.json): "New agent signer" (every signature the old one made void), triage, the agent paid LA-2010 and LA-2011 with the new signer, the CSV export; no page errors. [`payments.csv`](payments.csv) now has 6 rows; [`status-after-console.log`](status-after-console.log) |

`npm run verify` re-checks this desk: its bytecode against `contracts/InvoiceDeskV5.sol`, every payment in
`payments.csv` (`paid()` true, each transaction re-read), and that the agent's classical key alone is
`BadAgentSignature` here too, and that the signer the desk names is the one the Console rotated to, with the agent paying after. In this run `desk.mjs run` signed on the same machine as the agent; GETTING_STARTED
shows how to keep the signer on another host, as the live agent does.
