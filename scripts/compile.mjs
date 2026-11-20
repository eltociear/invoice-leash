// Compile contracts/InvoiceDesk.sol with solc-js into build/InvoiceDesk.json (abi + bytecode).
import solc from "solc";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
const src = readFileSync(new URL("../contracts/InvoiceDesk.sol", import.meta.url), "utf8");
const input = {
  language: "Solidity",
  sources: { "InvoiceDesk.sol": { content: src } },
  settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "paris",
    outputSelection: { "*": { InvoiceDesk: ["abi", "evm.bytecode.object"] } } },
};
const out = JSON.parse(solc.compile(JSON.stringify(input)));
const errs = (out.errors ?? []).filter((e) => e.severity === "error");
for (const e of out.errors ?? []) console.error(e.formattedMessage);
if (errs.length) process.exit(1);
const c = out.contracts["InvoiceDesk.sol"].InvoiceDesk;
mkdirSync(new URL("../build", import.meta.url), { recursive: true });
writeFileSync(new URL("../build/InvoiceDesk.json", import.meta.url),
  JSON.stringify({ abi: c.abi, bytecode: "0x" + c.evm.bytecode.object, compiler: solc.version() }, null, 2));
console.log(`compiled InvoiceDesk: ${c.evm.bytecode.object.length / 2} bytes (solc ${solc.version()})`);
