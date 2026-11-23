// Mutation check for InvoiceDeskV2: inject one bug at a time and confirm `forge test` fails.
//   node scripts/mutate.mjs > runs/mutation.txt
// Restores the contract after every mutant (and on any error). Needs Foundry (forge on PATH or ~/.foundry/bin).
import { readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const FILE = new URL("../contracts/InvoiceDeskV2.sol", import.meta.url);
const ORIGINAL = readFileSync(FILE, "utf8");
const forge = spawnSync("sh", ["-c", "command -v forge || echo ~/.foundry/bin/forge"]).stdout.toString().trim();

const PAID_CHECK = "        if (paid[payer][id]) revert AlreadyPaid(id);\n";
const MUTANTS = [
  ["signature check removed", (s) => s.replace("if (!PQC_VERIFY.pqcVerify(", "if (false && !PQC_VERIFY.pqcVerify(")],
  ["replay check moved before the signature", (s) => s.replace(PAID_CHECK, "").replace("        if (!approved[payer][vendor])", PAID_CHECK + "        if (!approved[payer][vendor])")],
  ["vendor key: proof of possession not required", (s) => s.replace("!registered || !proven ||", "!registered ||")],
  ["vendor key: algorithm not checked", (s) => s.replace("|| alg != ALG_ML_DSA_87)", ")")],
  ["currency left out of the signed bytes", (s) => s.replace("payer, vendor, token, amount, id, dueBy);\n    }", "payer, vendor, amount, id, dueBy);\n    }")],
  ["ERC-20 return value ignored", (s) => s.replace("if (!ok || (ret.length != 0 && !abi.decode(ret, (bool))))", "if (!ok)")],
  ["QOR sent along with an fUSD invoice accepted", (s) => s.replace("if (msg.value != native)", "if (false && msg.value != native)")],
  ["any account may pay for any payer", (s) => s.replace("if (byAgent && !isAgent[payer][msg.sender])", "if (false && byAgent && !isAgent[payer][msg.sender])")],
  ["agents' daily spend not recorded", (s) => s.replace("spentByAgents[payer][token][day] = s + amount;", "spentByAgents[payer][token][day] = s;")],
  ["per-payment limit ignored", (s) => s.replace("if (amount > l.perPayment)", "if (false && amount > l.perPayment)")],
  ["agents may pay in native QOR", (s) => s.replace("if (token == address(0)) revert AgentCannotPayNative();", "")],
  ["daily limit on a shifted day (not the UTC calendar day)", (s) => s.replace("uint256 day = block.timestamp / 1 days;", "uint256 day = (block.timestamp + 1 hours) / 1 days;")],
  ["invoice not marked paid", (s) => s.replace("paid[payer][id] = true;", "paid[payer][id] = false;")],
  ["token without code accepted", (s) => s.replace("if (token.code.length == 0) revert TransferFailed();", "")],
];

const test = () => {
  const r = spawnSync(forge, ["test", "--match-contract", "InvoiceDeskV2Test"], { encoding: "utf8", cwd: new URL("..", import.meta.url).pathname });
  const out = r.stdout + r.stderr;
  return { failed: r.status !== 0, failing: [...new Set([...out.matchAll(/\[FAIL.*?\] (test\w+)\(/g)].map((m) => m[1]))], compiled: !/Compiler run failed|Error \(/.test(out) };
};

let caught = 0;
try {
  const base = test();
  if (base.failed) throw new Error("the unmutated suite fails; fix that first");
  console.log(`InvoiceDeskV2 mutation check (forge test --match-contract InvoiceDeskV2Test), ${new Date().toISOString().slice(0, 10)}`);
  console.log("unmutated: all tests pass\n");
  for (const [name, f] of MUTANTS) {
    const m = f(ORIGINAL);
    if (m === ORIGINAL) throw new Error(`mutant "${name}" did not change the source`);
    writeFileSync(FILE, m);
    const r = test();
    writeFileSync(FILE, ORIGINAL);
    const ok = r.failed && r.compiled;
    if (ok) caught++;
    console.log(`${ok ? "CAUGHT " : "MISSED "} ${name}${r.compiled ? "" : " (did not compile)"}\n         failing: ${r.failing.join(", ") || "-"}`);
  }
} finally {
  writeFileSync(FILE, ORIGINAL);
}
console.log(`\n${caught} of ${MUTANTS.length} mutants caught`);
process.exitCode = caught === MUTANTS.length ? 0 : 1;
