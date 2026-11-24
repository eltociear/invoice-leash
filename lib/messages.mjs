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

/**
 * Verify against the chain. Returns { ok, why }. Never throws.
 * - `company` (qor1…): if given, the signer must be that account. Without it, any registered signer passes,
 *   which proves only who signed, not that they have any authority.
 * - The chain id is always this chain's (a caller-supplied chainId is not trusted).
 * - The signer's ML-DSA-87 key must have proven possession.
 * - A line "valid until: <ISO date>" in the text is enforced, so an old instruction cannot be replayed later.
 */
export async function verifyCompanyMessage({ signer, text, signature, chainId }, { company } = {}) {
  try {
    if (chainId !== undefined && chainId !== CHAIN_ID) return { ok: false, why: `signed for chain ${chainId}, not ${CHAIN_ID}` };
    if (company && signer !== company) return { ok: false, why: `signed by ${signer}, which is not the company (${company})` };
    const until = /^valid until: *(.+)$/im.exec(String(text))?.[1];
    if (until !== undefined) {
      const t = Date.parse(until);
      if (Number.isNaN(t)) return { ok: false, why: `unreadable "valid until" date: ${until}` };
      if (t < Date.now()) return { ok: false, why: `expired: valid until ${new Date(t).toISOString()}` };
    }
    const r = await verifyMessageWithChain({ rest: REST, chainId: CHAIN_ID, signer, data: text, signature });
    if (!r.possessionProven) return { ok: false, why: `${signer}'s ML-DSA-87 key has not proven possession` };
    return { ok: true, why: `hybrid signature valid; ML-DSA-87 checked against ${signer}'s key on chain (possession proven)${until ? `; valid until ${until}` : ""}` };
  } catch (e) {
    const why = String(e?.message ?? e).replace(/\s+/g, " ").slice(0, 240);
    // could not ask the chain: not a verdict (callers treat it as "not authentic" but must say why)
    return { ok: false, network: /request to .* failed|fetch failed|ECONN|ETIMEDOUT|EAI_AGAIN|socket hang up|timed? ?out|HTTP 5\d\d/i.test(why), why };
  }
}
