# Run Invoice Leash for your own company

This guide sets up your own payment desk on the QoreChain testnet (`qorechain-diana`): your company, your
vendors, your agent. It takes about 15 minutes. Every step below was run end to end on the testnet, and
the output is in [`runs/own-company/`](runs/own-company/). `npm run verify` re-checks that run every day.

Two programs, used by two parties:

| Who | Program | Keys live in |
|---|---|---|
| your company | `node desk.mjs …` | `~/.config/leash-desk/keys.env` (or `$LEASH_HOME`) |
| each vendor, on its own machine | `node vendor.mjs …` | `~/.config/leash-vendor/keys.env` (or `$LEASH_VENDOR_HOME`) |

Neither writes to this repository. `node desk.mjs status` always tells you the next step.

## What you need

- Node.js 20 or later, and this repository: `git clone --recurse-submodules https://github.com/eltociear/invoice-leash && cd invoice-leash && npm install`
- Testnet QOR and fUSD from the [QoreChain faucet](https://dashboard.qorechain.io/faucet). Test tokens have no value.

## 1. The company

```sh
node desk.mjs init        # makes the company's keys; prints the company address
```

Fund that address from the faucet. You need **about 10 QOR** for fees, plus the **fUSD** you want the desk
to pay invoices with. The faucet's fUSD arrives as a bank coin, which `setup` handles.

```sh
node desk.mjs setup --per-payment 100 --daily 250 --allowance 1000 --float 400 --hours 168
```

What `setup` does, in order. It stops with a clear message if anything is missing, and you can run it
again: it skips what is done.

1. Registers the company's ML-DSA-87 key. After this, the chain refuses any company transaction without an
   ML-DSA-87 signature.
2. Sends fee money: 3 QOR to the **fee wallet**, which relays the agent's requests, and 1 QOR to the
   **agent account**.
3. Registers their ML-DSA-87 keys.
4. Deploys **your InvoiceDeskV3**, in a window that admits one transaction.
5. In a window scoped to the desk and fUSD, it names the agent account as your agent, sets its limits
   (`--per-payment`, `--daily`, in fUSD) and gives the desk an fUSD allowance (`--allowance`, the total it
   may ever pull).
6. Links the agent's key to the agent account for `--hours`. The key may make one call, `pay` on your
   desk, and move no QOR or fUSD.
7. Publishes the agent account's ML-KEM-1024 key, so vendors can seal invoices to it.
8. **Treasury and float.** Keeps `--float` fUSD as ERC-20, the balance the desk pays from, and the rest
   as the bank coin, which moves only with your ML-DSA-87 signature. Change it later with
   `node desk.mjs treasury <float>`.

## 2. Each vendor

The vendor does this on its own machine. Its key never reaches you.

```sh
node vendor.mjs init       # prints the vendor's address; fund it with about 1 QOR (faucet)
node vendor.mjs register   # registers its ML-DSA-87 key, with proof of possession
```

The vendor sends you its address. You approve it:

```sh
node desk.mjs vendor add 0x8bb12d258f65fbbaad6bc674f7bdebf783dc8993 "Northwind Hosting"
```

`vendor add` refuses an address with no proven ML-DSA-87 key, because the desk could never pay it.

## 3. Invoices

The vendor signs each invoice for your desk and your company. With `--seal-to` it is also sealed, so only
your agent can read it. Your agent account's address is in `node desk.mjs status`.

```sh
node vendor.mjs sign --desk <your desk> --payer <your company address> --amount 30 --ref NW-1001 --due 2027-01-31
node vendor.mjs sign ... --ref NW-1003 --seal-to <your agent account, qor1…>
```

The vendor sends you the file, by email or any other channel. You add it to your inbox:

```sh
node desk.mjs check NW-1001.json    # optional: verifies the ML-DSA-87 signature against the vendor's key on chain
node desk.mjs inbox add NW-1001.json
```

## 4. Triage, pay, approve

```sh
node desk.mjs triage
```

```
  0  AGENT PAYS      NW-1001       30 fUSD   Northwind Hosting
  1  NEEDS A PERSON  NW-1002       80 fUSD   Northwind Hosting   over the agent's per-payment limit. A person can: node desk.mjs pay 1
  2  AGENT PAYS      NW-1003       20 fUSD   Northwind Hosting   sealed (opened with the agent's ML-KEM-1024 key)
  3  REJECTED        MS-77         25 fUSD                       UnknownVendor
  4  REJECTED        NW-1001       45 fUSD   Northwind Hosting   BadSignature   (the amount was edited after signing)
```

Each verdict is your desk's own answer, from a dry run as the agent and as the company. Then:

```sh
node desk.mjs run      # the agent pays what triage marked AGENT PAYS, and nothing else
node desk.mjs pay 1    # a person pays an approved over-limit invoice, as the company
```

## 5. Run the agent from an AI model (MCP)

```sh
node desk.mjs mcp > .mcp.json     # the invoice-leash MCP server, for your inbox and your desk
claude                            # or any MCP client: list_inbox, check_invoice, pay_invoice, ...
```

The server holds only the agent's key. Whatever the model decides, the chain and your desk enforce the
limits. Its log is kept next to your `desk.json`.

## 6. Accounting

```sh
node desk.mjs export payments.csv
```

```
paid_at_utc,vendor_name,vendor,invoice_ref,invoice_id,amount,currency,paid_by,tx
2026-11-24T04:27:33.000Z,Northwind Hosting,0x8BB1…,NW-1001,0x590c…,30.0,fUSD,agent,D7D404F7…
2026-11-24T04:28:49.000Z,Northwind Hosting,0x8BB1…,NW-1002,0x31ca…,80.0,fUSD,company,0x5df0a0f4…
```

Every row comes from the chain, not from a local log. The company's own payments come from the desk's
`InvoicePaid` events. The agent's come from the relayer's transactions, checked against the desk's
`paid()` record: an authenticator-relayed EVM call leaves no log that `eth_getLogs` returns (measured on
diana). A payment with no matching invoice in your inbox is flagged.

## Late invoices, and vendors that use the same invoice numbers

Your desk is an **InvoiceDeskV3**:
- **Invoice numbers are per vendor.** Two vendors may both send `INV-2001`, and both are paid, each once.
- **Overdue invoices.** The agent never pays after the due date (`PastDue`), but the company can settle
  an overdue invoice in person: `triage` marks it NEEDS A PERSON, then run `node desk.mjs pay <n>`. A
  vendor re-issues an overdue invoice with `vendor.mjs sign ... --overdue`.
- A zero-amount invoice is refused (`ZeroAmount`). The desk also checks that the vendor received exactly
  the invoiced amount.

All of this was run on the testnet: [`runs/own-company-v3/`](runs/own-company-v3/).

**Set up before V3?** `node desk.mjs upgrade` deploys a V3 desk and copies your vendors, agent, limits
and allowance. It switches the agent off on the old desk, sets the old allowance to 0, and relinks the
agent's key. `export` keeps the old desk's history. Then run `node desk.mjs inbox archive`, and ask
vendors to re-sign any open invoices for the new desk address.

## In the browser: the Desk Console

```sh
node desk.mjs serve      # prints a link to https://eltociear.github.io/invoice-leash/app.html#local=…&token=…
```

Open the link to run your desk from the page: the agent on, off or frozen, vendors, limits, the float, the
inbox (including invoices signed in the page by the public test vendor), triage, "pay in person", and the
CSV. The page talks only to `127.0.0.1`, and your keys stay on your machine. Only the console's origin may
call the signer, and only with the printed token. Why not MetaMask: QoreChain refuses every transaction
without an ML-DSA-87 key, including a plain EVM wallet's ([`runs/probes/no-pq-evm.json`](runs/probes/no-pq-evm.json)).

## Day to day

| Task | Command |
|---|---|
| What is set up, and what to do next | `node desk.mjs status` |
| Stop everything now: agent off in the desk, its key revoked, windows closed | `node desk.mjs freeze` (and `unfreeze`) |
| Stop the agent in the desk only (one transaction) | `node desk.mjs agent off` (and `agent on`) |
| The agent's link expires: renew it | `node desk.mjs agent link [hours]` |
| Change limits | `node desk.mjs limits <perPayment> <daily>` |
| Stop paying a vendor | `node desk.mjs vendor remove <address>` |
| Refill the float from the treasury | `node desk.mjs treasury <float>` |
| Raise the total the desk may pull | `node desk.mjs allowance <fUSD>` |

## What it does not do yet

Be clear about these before relying on it:

- **Testnet only, fUSD only.** Your vendors must also be on QoreChain, with a registered ML-DSA-87 key.
  There is no bank or fiat rail, and no way to pay a vendor that is not on chain.
- **Exact amounts.** No partial payments and no credit notes. The amount paid is the amount signed.
- **One company key.** There is no multi-signature approval. `pay` by a person is one key holder.
- **Inbox from files.** Invoices arrive as files (`inbox add`). Reading them from a mailbox is up to you.
