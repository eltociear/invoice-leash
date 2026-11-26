// The numbers the documents state, against where they come from. Offline: no network.
//   verify checks  <- the last line of runs/verify-latest.txt (npm run verify | tee runs/verify-latest.txt)
//   drill attacks  <- runs/qday-drill.json
//   Foundry tests  <- `function test…` in test/*.t.sol;  invariants <- `function invariant_…`
//   mutants        <- runs/mutation.txt
//   public agent signatures <- runs/signature-sweep.json
// A stale count in any document fails `npm test`.
import { readFileSync, readdirSync } from "node:fs";

const root = new URL("../", import.meta.url);
const read = (p) => readFileSync(new URL(p, root), "utf8");
const sol = readdirSync(new URL("test/", root)).filter((f) => f.endsWith(".t.sol")).map((f) => read(`test/${f}`)).join("\n");
const truth = {
  checks: Number(read("runs/verify-latest.txt").match(/✓ (\d+) checks passed, 0 failed/)[1]),
  attacks: JSON.parse(read("runs/qday-drill.json")).attempts.length,
  campaign: JSON.parse(read("runs/campaign.json")).count,
  tests: (sol.match(/function test\w*\(/g) ?? []).length,
  invariants: (sol.match(/function invariant_\w*\(/g) ?? []).length,
  mutants: Number(read("runs/mutation.txt").match(/(\d+) of \1 mutants caught/)[1]),
  mutantsV3: Number(read("runs/mutation-v3.txt").match(/(\d+) of \1 mutants caught/)[1]),
  mutantsV4: Number(read("runs/mutation-v4.txt").match(/(\d+) of \1 mutants caught/)[1]),
  mutantsV5: Number(read("runs/mutation-v5.txt").match(/(\d+) of \1 mutants caught/)[1]),
  signatures: JSON.parse(read("runs/signature-sweep.json")).signatures,
};
const docs = ["README.md", "EVIDENCE.md", "JUDGES.md", "DECISIONS.md", "GETTING_STARTED.md", "V1.md", "THREAT_MODEL.md", "AI_USAGE.md", "QUANTUM_READINESS.md", "scripts/site.mjs", "scripts/lab.mjs"];
const rules = [
  ["checks", /(\d+) (?:read-only )?checks\b/g],
  ["attacks", /(?<![\d,])(\d+) attacks\b/g],
  ["campaign", /(\d[\d,]*) (?:random attacks|dry-run tamperings)\b/g],
  ["attacks", /(\d+) of \1 refused/g],
  ["attacks", /attacks with every classical key, (\d+) refused/g],
  ["tests", /(\d+) Foundry tests/g],
  ["tests", /(\d+) tests \+ \d+ invariants/g],
  ["invariants", /(\d+) invariants\b/g],
  ["mutants", /(?<!V[345]: )\b(\d+) of \1 mutants/g],
  ["mutantsV3", /V3: (\d+) of \1\b/g],
  ["mutantsV4", /V4: (\d+) of \1\b/g],
  ["mutantsV5", /V5: (\d+) of \1\b/g],
  ["mutants", /(\d+)-mutant\b/g],
  ["signatures", /(\d+) public agent signatures/g],
  ["signatures", /verify sends all (\d+) again/g],
  ["signatures", /signature-sweep\.json`\]\(runs\/signature-sweep\.json\): (\d+)[, ]/g],
  ["signatures", /\| public agent signatures \| (\d+),/g],
];
let bad = 0, seen = 0;
for (const f of docs) {
  const lines = read(f).split("\n");
  lines.forEach((line, i) => {
    for (const [k, re] of rules) for (const m of line.matchAll(re)) {
      seen++;
      if (Number(m[1].replaceAll(",", "")) !== truth[k]) { bad++; console.error(`✗ ${f}:${i + 1}: "${m[0]}", but ${k} = ${truth[k]}`); }
    }
  });
}
if (seen < 10) { console.error(`✗ only ${seen} counts found: the patterns no longer match the documents`); bad++; }
console.log(`${bad ? "✗" : "✓"} ${seen} stated counts checked against their sources ${JSON.stringify(truth)}`);
process.exitCode = bad ? 1 : 0;
