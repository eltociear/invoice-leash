// Compile contracts/*.sol with solc-js into build/<Contract>.json (abi, bytecode, deployedBytecode).
// InvoiceDesk is v1 (QOR only); InvoiceDeskV2 adds ERC-20 (fUSD) invoices; InvoiceDeskV3 keys invoices per vendor and lets the payer settle late ones.
import solc from "solc";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
for (const name of ["InvoiceDesk", "InvoiceDeskV2", "InvoiceDeskV3"]) {
  const src = readFileSync(new URL(`../contracts/${name}.sol`, import.meta.url), "utf8");
  const input = {
    language: "Solidity",
    sources: { [`${name}.sol`]: { content: src } },
    settings: { optimizer: { enabled: true, runs: 200 }, evmVersion: "paris",
      outputSelection: { "*": { [name]: ["abi", "evm.bytecode.object", "evm.deployedBytecode.object"] } } },
  };
  const out = JSON.parse(solc.compile(JSON.stringify(input)));
  const errs = (out.errors ?? []).filter((e) => e.severity === "error");
  for (const e of out.errors ?? []) console.error(e.formattedMessage);
  if (errs.length) process.exit(1);
  const c = out.contracts[`${name}.sol`][name];
  mkdirSync(new URL("../build", import.meta.url), { recursive: true });
  writeFileSync(new URL(`../build/${name}.json`, import.meta.url),
    JSON.stringify({ abi: c.abi, bytecode: "0x" + c.evm.bytecode.object, deployedBytecode: "0x" + c.evm.deployedBytecode.object, compiler: solc.version() }, null, 2));
  console.log(`compiled ${name}: ${c.evm.bytecode.object.length / 2} bytes (solc ${solc.version()})`);
}
