# AI usage

## In the product

`node leash.mjs run --llm` uses Claude as the agent's decider: it reads the inbox and returns a plan
of `pay` / `send` / `call` / `skip` actions. The project's claim is that the outcome does not depend
on the model, so the same inbox is also run with a deliberately compromised decider that obeys
every instruction, and the chain's refusals are the same.

## In building it

This project was built with Claude Code (Anthropic) as a coding assistant: reading the QoreChain
SDK typings and the workshop example, drafting the contract, the CLI and this documentation, and
running the testnet steps. The design (moving every limit out of the agent, scoping the agent to
the `pay` selector because the agent acts as the owner's account, checking invoice signatures
before the replay guard) and every result in `runs/` were checked against the live
`qorechain-diana` testnet, not taken from the model's word.
