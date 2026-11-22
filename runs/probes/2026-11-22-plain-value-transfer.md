# Probe: a plain EVM value transfer by the agent key (no call data)

2026-11-22. Rule on qor1khdfqy8czenz9gstyy8ye2swxpee2xwslh0uzn: permissions `evm`, per-tx 1 QOR,
daily 2.5 QOR, `allowed_evm_calls = [InvoiceDesk.pay]`.

The agent key sent 0.01 QOR to a fresh random address with empty call data:
EXECUTED, https://explore.qore.network/tx/779FAF6E8871B3FFF1D0D2D129AC904529E78E5198718C1DD630676E05AD4CEC

`allowed_evm_calls` scopes calls *with call data*; a value-only transfer is not a call, so it was
bounded only by the value limits. The v1 demo's "send 50 QOR" was a Cosmos `MsgSend` (refused: no
`send` permission) and never exercised this path. Fixed in v2 by the rule's `allowed_denoms`.
