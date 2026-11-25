# A third company, set up from nothing on InvoiceDeskV4

Run on 2026-11-25 by following [GETTING_STARTED.md](../../GETTING_STARTED.md) step by step, with fresh keys
(`LEASH_HOME`, `LEASH_VENDOR_HOME`) and nothing reused from the other desks. The company was funded the way
the faucet would (12 QOR and 100 fUSD as the bank coin, from the demo company:
[1BBD0C8D…](https://explore.qore.network/tx/1BBD0C8D7DCE6FC97052A27F7986F3E9816979E7F7E795EDA35C0A3BE4FE15F3)).

| Step | Command | Record |
|---|---|---|
| keys | `desk.mjs init` | prints the company address |
| desk | `desk.mjs setup --per-payment 30 --daily 60 --allowance 200 --float 60 --hours 720` | [`setup.log`](setup.log): ML-DSA-87 keys registered, InvoiceDeskV4 deployed at [`0xd8a723c9…`](https://explore.qore.network/address/0xd8a723c91Af58A885d8E87509E7B770559c0C353), agent signer named, agent key linked (one call: the desk's `pay`), KEM key published, float 60 / treasury 40. The network dropped once; running `setup` again resumed where it stopped |
| vendor | `vendor.mjs init`, `register`; `desk.mjs vendor add` | [`vendor-register.log`](vendor-register.log), [`vendor-add.log`](vendor-add.log): Harbor Cloud, its own ML-DSA-87 key |
| invoices | `vendor.mjs sign …` (one sealed with `--seal-to`, one re-issued `--overdue`); an edited copy; one from a vendor the company never approved | [`invoices/`](invoices/), [`inbox-add.log`](inbox-add.log) |
| triage | `desk.mjs triage` | [`triage.log`](triage.log): 2 AGENT PAYS, 2 NEEDS A PERSON (over the limit; past due), 2 REJECTED (`BadSignature`, `UnknownVendor`) |
| agent | `desk.mjs run` | [`run.log`](run.log): HC-1001 and the sealed HC-1003 paid, each with the agent signer's ML-DSA-87 signature |
| person | `desk.mjs pay 3`, then `pay 1` | [`pay.log`](pay.log): the overdue invoice settled in person; the 45 fUSD one first refused with the reason and the fix (`TransferFailed`: float too low), then paid after `desk.mjs treasury 50` ([`treasury.log`](treasury.log)) |
| console | the [Desk Console](https://eltociear.github.io/invoice-leash/app.html) through `desk.mjs serve`, in a real browser | [`../console-e2e-v4.json`](../console-e2e-v4.json): the public test vendor approved, an invoice signed in the page, a forgery, triage, the agent paid two, export; then the public vendor removed |
| accounting | `desk.mjs export` | [`payments.csv`](payments.csv): 6 payments, from the chain |
| final | `desk.mjs triage`, `status` | [`triage-after.log`](triage-after.log), [`status.log`](status.log) |

What this run changed in `desk.mjs`: every refusal now comes with what it means and what to do
(`TransferFailed: the transfer would fail: the fUSD float … node desk.mjs treasury <float>`); a network
failure says that nothing was lost and the command can be run again; `status` names the desk's version and
its agent signer; and `triage` reports a paid invoice as paid even after its vendor is removed, while an
edited copy of it stays `REJECTED`.

`npm run verify` re-checks this desk: its bytecode, every payment in `payments.csv`, and that the agent's
classical key alone is refused here too.
