// Sealed invoices: vendors encrypt invoices to the agent account's ML-KEM-1024 key, published in
// QoreChain's KEM key registry (QoreSeal, FIPS 203). Email is readable by anyone on the path, and an
// adversary can store it today and decrypt it after Q-Day ("harvest now, decrypt later"); a sealed
// invoice's payee, amount and number stay confidential. Sealing is NOT authenticity: anyone can seal to
// a public key. Whether an invoice is genuine is still decided by its ML-DSA-87 signature, on chain.
import { open, parseEnvelope, envelopeToText, envelopeFromText, sealKeysFromSeed } from "@qorechain/qoreseal";
import { fetchKemKey, sealToAddresses } from "@qorechain/qoreseal/network";
import { CHAIN_ID, REST, ensureHexKey } from "./chain.mjs";

export const PURPOSE = "invoice-leash/invoice-v1";

/** The agent's ML-KEM-1024 keys (seed in the keys file as `agentkem`). Reading power only: no spending. */
export const agentKemKeys = () => sealKeysFromSeed(ensureHexKey("agentkem"));

/** MsgRegisterKEMKey for `sender` (the agent account), as the SDK's registry encodes it. */
export const registerKemMsg = (sender, keys) => ({ typeUrl: "/qorechain.pqc.v1.MsgRegisterKEMKey", value: { sender, algorithmId: 2, publicKey: keys.mlkemPublicKey } });

/** Seal a signed invoice (JSON) to an address, using the ML-KEM-1024 key that address registered on chain. */
export async function sealInvoice(address, invoice) {
  const env = await sealToAddresses({ rest: REST, chainId: CHAIN_ID, purpose: PURPOSE, mode: "mlkem", recipients: [{ address }], plaintext: new TextEncoder().encode(JSON.stringify(invoice)) });
  return envelopeToText(env);
}

/** Open a sealed invoice with the agent's keys. Throws if it was not sealed to them. */
export const openInvoice = (text, keys = agentKemKeys()) => JSON.parse(new TextDecoder().decode(open({ chainId: CHAIN_ID, purpose: PURPOSE, envelope: envelopeFromText(text), keys })));

/** Structure only (no key needed): mode, recipients, sizes. */
export const describeEnvelope = (text) => { const e = parseEnvelope(envelopeFromText(text)); return { mode: e.mode, recipients: e.entries.length, bytes: envelopeFromText(text).length, ciphertextBytes: e.ciphertext.length }; };

export const kemKeyOf = (address) => fetchKemKey({ rest: REST, address });
