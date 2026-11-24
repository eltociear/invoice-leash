// Mutation check: inject one bug at a time into a desk contract and confirm `forge test` fails.
//   node scripts/mutate.mjs      > runs/mutation.txt      (InvoiceDeskV2)
//   node scripts/mutate.mjs v3   > runs/mutation-v3.txt   (InvoiceDeskV3: V2's mutants, adapted, plus V3's own)
//   node scripts/mutate.mjs v4   > runs/mutation-v4.txt   (InvoiceDeskV4: V3's, adapted, plus the agent signature's)
// Restores the contract after every mutant (and on any error). Needs Foundry (forge on PATH or ~/.foundry/bin).
// Never run it while `npm run verify` runs: it edits the contract in place.
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const V4 = process.argv[2] === "v4", V3 = process.argv[2] === "v3" || V4;
const NAME = V4 ? "InvoiceDeskV4" : V3 ? "InvoiceDeskV3" : "InvoiceDeskV2";
const FILE = new URL(`../contracts/${NAME}.sol`, import.meta.url);
const ORIGINAL = readFileSync(FILE, "utf8");
const forge = spawnSync("sh", ["-c", "command -v forge || echo ~/.foundry/bin/forge"]).stdout.toString().trim();

const PAID = V3 ? "paid[payer][vendor][id]" : "paid[payer][id]";
const PAID_CHECK = `        if (${PAID}) revert AlreadyPaid(id);\n`;
const MUTANTS = [
  ["signature check removed", (s) => s.replace("if (!PQC_VERIFY.pqcVerify(", "if (false && !PQC_VERIFY.pqcVerify(")],
  ["replay check moved before the signature", (s) => V4 ? s.replace(PAID_CHECK, "").replace("        _vendorSignature(", PAID_CHECK + "        _vendorSignature(") : s.replace(PAID_CHECK, "").replace("        if (!approved[payer][vendor])", PAID_CHECK + "        if (!approved[payer][vendor])")],
  ["vendor key: proof of possession not required", (s) => s.replace("if (!registered || !proven || alg != ALG_ML_DSA_87) revert VendorKeyNotProven", "if (!registered || alg != ALG_ML_DSA_87) revert VendorKeyNotProven")],
  ["vendor key: algorithm not checked", (s) => s.replace("|| alg != ALG_ML_DSA_87) revert VendorKeyNotProven", ") revert VendorKeyNotProven")],
  ["currency left out of the signed bytes", (s) => s.replace("payer, vendor, token, amount, id, dueBy);\n    }", "payer, vendor, amount, id, dueBy);\n    }")],
  ["ERC-20 return value ignored", (s) => s.replace("if (!ok || (ret.length != 0 && !abi.decode(ret, (bool))))", "if (!ok)")],
  ["QOR sent along with an fUSD invoice accepted", (s) => s.replace("if (msg.value != native)", "if (false && msg.value != native)")],
  ["any account may pay for any payer", (s) => s.replace("if (byAgent && !isAgent[payer][msg.sender])", "if (false && byAgent && !isAgent[payer][msg.sender])")],
  ["agents' daily spend not recorded", (s) => s.replace("spentByAgents[payer][token][day] = s + amount;", "spentByAgents[payer][token][day] = s;")],
  ["per-payment limit ignored", (s) => s.replace("if (amount > l.perPayment)", "if (false && amount > l.perPayment)")],
  ["agents may pay in native QOR", (s) => s.replace("if (token == address(0)) revert AgentCannotPayNative();", "")],
  ["daily limit on a shifted day (not the UTC calendar day)", (s) => s.replace("uint256 day = block.timestamp / 1 days;", "uint256 day = (block.timestamp + 1 hours) / 1 days;")],
  ["invoice not marked paid", (s) => s.replace(`${PAID} = true;`, `${PAID} = false;`)],
  // In V3 this mutant is equivalent: reading the vendor's balance from an address without code fails the
  // same way (TransferFailed), so no test can tell them apart. Kept, and reported as such, not counted.
  ["token without code accepted", (s) => s.replace("if (token.code.length == 0) revert TransferFailed();", ""), V3 && "the vendor-balance check refuses it the same way (TransferFailed)"],
  ...(V3 ? [
    ["V3: agents may pay past due", (s) => s.replace("if (block.timestamp > dueBy) revert PastDue(dueBy);", "")],
    ["V3: past due refused for the payer too (no late settlement)", (s) => s.replace("        if (byAgent) {\n            if (block.timestamp > dueBy) revert PastDue(dueBy);", "        if (block.timestamp > dueBy) revert PastDue(dueBy);\n        if (byAgent) {")],
    ["V3: invoice ids not keyed by vendor (V2's collision)", (s) => s.replaceAll("paid[payer][vendor][id]", "paid[payer][address(0)][id]")],
    ["V3: zero-amount invoice accepted", (s) => s.replace("if (amount == 0) revert ZeroAmount();", "")],
    ["V3: what the vendor received not checked", (s) => s.replace("if (_balanceOf(token, vendor) != before + amount) revert TransferFailed();", "")],
  ] : []),
  ...(V4 ? [
    ["V4: the agent's signature not checked", (s) => s.replace("if (byAgent) _agentSignature(", "if (false) _agentSignature(")],
    ["V4: the agent signer's key: proof of possession not required", (s) => s.replace("if (!registered || !proven || alg != ALG_ML_DSA_87) revert AgentKeyNotProven", "if (!registered || alg != ALG_ML_DSA_87) revert AgentKeyNotProven")],
    ["V4: no signer named is not refused", (s) => s.replace("if (signer == address(0)) revert AgentSignerNotSet(msg.sender);", "")],
    ["V4: the agent's signed bytes omit the amount", (s) => s.replace("payer, agent, vendor, token, amount, id);", "payer, agent, vendor, token, uint256(0), id);")],
    ["V4: the agent's signed bytes omit the invoice id", (s) => s.replace("payer, agent, vendor, token, amount, id);", "payer, agent, vendor, token, amount, bytes32(0));")],
    ["V4: the agent's signed bytes omit the token", (s) => s.replace("payer, agent, vendor, token, amount, id);", "payer, agent, vendor, address(0), amount, id);")],
    ["V4: the agent's signed bytes omit the agent", (s) => s.replace("payer, agent, vendor, token, amount, id);", "payer, address(0), vendor, token, amount, id);")],
  ] : []),
];

const test = () => {
  const r = spawnSync(forge, ["test", "--match-contract", `${NAME}Test`], { encoding: "utf8", cwd: new URL("..", import.meta.url).pathname });
  const out = r.stdout + r.stderr;
  return { failed: r.status !== 0, failing: [...new Set([...out.matchAll(/\[FAIL.*?\] (\w+)\(/g)].map((m) => m[1]))], compiled: !/Compiler run failed|Error \(/.test(out) };
};

let caught = 0, counted = 0;
try {
  const base = test();
  if (base.failed) throw new Error("the unmutated suite fails; fix that first");
  console.log(`${NAME} mutation check (forge test --match-contract ${NAME}Test), ${new Date().toISOString().slice(0, 10)}`);
  console.log("unmutated: all tests pass\n");
  for (const [name, f, equivalent] of MUTANTS) {
    const m = f(ORIGINAL);
    if (m === ORIGINAL) throw new Error(`mutant "${name}" did not change the source`);
    writeFileSync(FILE, m);
    const r = test();
    writeFileSync(FILE, ORIGINAL);
    const ok = r.failed && r.compiled;
    if (equivalent && !ok) { console.log(`EQUIV.  ${name}\n         not counted: ${equivalent}`); continue; }
    if (ok) caught++;
    counted++;
    console.log(`${ok ? "CAUGHT " : "MISSED "} ${name}${r.compiled ? "" : " (did not compile)"}\n         failing: ${r.failing.join(", ") || "-"}`);
  }
} finally {
  writeFileSync(FILE, ORIGINAL);
}
const eq = MUTANTS.length - counted;
console.log(`\n${caught} of ${counted} mutants caught${eq ? ` (${eq} equivalent, not counted)` : ""}`);
process.exitCode = caught === counted ? 0 : 1;
