// Authenticated messages between the company and its agent: QoreSign message-signing-v1 (the format
// QoreX's signArbitrary produces). Hybrid: secp256k1 over the ADR-36 document, plus ML-DSA-87 over
// "qorechain-msg-v1|<chain id>|<message>". The agent checks the ML-DSA-87 part against the key the
// claimed signer registered on chain, so "approved by the CFO" in an email body means nothing unless
// the company's post-quantum key signed it.
import { signMessage } from "@qorechain/qoresign";
import { verifyMessageWithChain } from "@qorechain/qoresign/network";
import { getBytes } from "ethers";
import { CHAIN_ID, REST } from "./chain.mjs";

/** Sign `text` as `acc` (an account() result). `as` lets a demo claim another signer (a forgery). */
export function signCompanyMessage(acc, text, as = acc.cosmos) {
  const classicalKey = { type: "eth_secp256k1", privateKey: getBytes(acc.privateKey), publicKey: getBytes(acc.publicKey) };
  return { signer: as, text, chainId: CHAIN_ID, signature: signMessage({ chainId: CHAIN_ID, signer: as, data: text, classicalKey, pqKey: { secretKey: acc.pqc.secretKey } }) };
}

/** Verify against the chain. Returns { ok, why }. Never throws. */
export async function verifyCompanyMessage({ signer, text, signature, chainId = CHAIN_ID }) {
  try {
    const r = await verifyMessageWithChain({ rest: REST, chainId, signer, data: text, signature });
    return { ok: true, why: `hybrid signature valid; ML-DSA-87 checked against ${signer}'s key on chain${r.possessionProven ? " (possession proven)" : ""}` };
  } catch (e) {
    return { ok: false, why: String(e?.message ?? e).replace(/\s+/g, " ").slice(0, 240) };
  }
}
