# Earlier attempts

Runs from while the demo was being built, kept as recorded. They are not the results:

- `12-13-15`: first design (2 QOR/day). The daily limit stopped the edited invoice and the replay before the contract could, so the signature and replay checks never got a turn. The daily limit was raised to 2.5 QOR and a tenth email added.
- `12-15-30`: the gas wallet ran out of fee money half way (each request was given 1.2M gas). Items 5 to 9 were never sent. That run also mislabelled those as chain refusals; the CLI now reports them as NOT SENT.
- `12-20-08`: the agent signed an EVM gas limit (800k) larger than what the relaying tx provisions for the call (~762k), so the chain refused all ten. Fixed by signing 650k.
