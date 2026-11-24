// Every inline script on the published pages must parse: a quote slip in a template literal once broke the
// live attack lab silently. Also checks the in-browser ML-DSA-87 bundle signs and verifies like the SDK.
import { readFileSync, readdirSync } from "node:fs";
import { pqcVerify, generatePqcKeypair } from "@qorechain/sdk";
const docs = new URL("../docs/", import.meta.url);
let n = 0;
for (const f of readdirSync(docs).filter((f) => f.endsWith(".html"))) {
  const html = readFileSync(new URL(f, docs), "utf8");
  for (const [, js] of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) {
    try { new Function(js); n++; } catch (e) { console.error(`✗ docs/${f}: ${e.message}`); process.exit(1); }
  }
}
// standalone page scripts (docs/*.js) must parse too
for (const f of readdirSync(docs).filter((f) => f.endsWith(".js"))) {
  try { new Function(readFileSync(new URL(f, docs), "utf8")); n++; } catch (e) { console.error(`✗ docs/${f}: ${e.message}`); process.exit(1); }
}
const { ml_dsa87 } = await import(new URL("vendor/mldsa87.min.js", docs));
const kp = generatePqcKeypair(new Uint8Array(32).fill(9)), msg = new TextEncoder().encode("invoice");
const sig = ml_dsa87.sign(msg, kp.secretKey);
if (sig.length !== 4627 || !pqcVerify(kp.publicKey, msg, sig)) { console.error("✗ docs/vendor/mldsa87.min.js does not match @qorechain/sdk"); process.exit(1); }
console.log(`✓ pages: ${n} inline scripts parse; the browser ML-DSA-87 bundle signs what @qorechain/sdk verifies`);
