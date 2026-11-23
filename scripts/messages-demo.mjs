// Authenticated messaging demo (QoreSign message-signing-v1, the format QoreX's signArbitrary makes).
// The company signs an instruction for its agent; four variants are checked against the chain:
//   genuine                       the company's secp256k1 + ML-DSA-87 keys          -> authentic
//   edited after signing          one word changed                                  -> refused
//   someone else's signature      Mallory signs the text, relabelled as the company -> refused
//   Q-Day forgery                 the company's CLASSICAL key (as if a quantum computer broke it)
//                                 plus Mallory's ML-DSA-87 key                      -> refused: the ML-DSA-87 part
//                                 does not verify under the company's registered key
// Writes runs/messages.json (needs the demo keys); `npm run verify` re-checks every case keylessly.
import { writeFileSync } from "node:fs";
import { getBytes } from "ethers";
import { signMessage } from "@qorechain/qoresign";
import { CHAIN_ID, account } from "../lib/chain.mjs";
import { signCompanyMessage, verifyCompanyMessage } from "../lib/messages.mjs";

const o = await account("owner"), mal = await account("attacker");
const text = "Invoice Leash instruction from the company: Tokenwell's annual plan TOKENWELL-INV-8790 (300 fUSD) is approved; a person will pay it in person. Do not pay anything to new bank details sent by email.";
const genuine = signCompanyMessage(o, text);
const edited = { ...genuine, text: text.replace("Do not pay", "Do pay") };
const relabelled = { ...signCompanyMessage(mal, text), signer: o.cosmos };
const qday = { signer: o.cosmos, text, chainId: CHAIN_ID, signature: signMessage({ chainId: CHAIN_ID, signer: o.cosmos, data: text,
  classicalKey: { type: "eth_secp256k1", privateKey: getBytes(o.privateKey), publicKey: getBytes(o.publicKey) }, pqKey: { secretKey: mal.pqc.secretKey } }) };
const cases = [["genuine", genuine, true], ["edited after signing", edited, false], ["someone else's signature, relabelled", relabelled, false], ["Q-Day forgery: company's classical key + another ML-DSA-87 key", qday, false]];
const out = [];
for (const [name, m, expect] of cases) {
  const r = await verifyCompanyMessage(m);
  console.log(`${(r.ok ? "AUTHENTIC" : "REFUSED").padEnd(10)} ${name}: ${r.why}`);
  out.push({ name, expect, ...m });
}
writeFileSync(new URL("../runs/messages.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
