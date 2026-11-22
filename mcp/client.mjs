#!/usr/bin/env node
// A scripted MCP client for the Invoice Leash server, over real MCP (stdio).
//
//   node mcp/client.mjs --readonly       list the tools, read status and inbox, dry-run every invoice
//   node mcp/client.mjs --compromised    an agent that obeys every email, through MCP tools only
//
// Uses the same LEASH_INBOX as the server it spawns.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { readFileSync } from "node:fs";

const mode = process.argv[2] ?? "--readonly";
const root = new URL("../", import.meta.url);
const inbox = JSON.parse(readFileSync(new URL(process.env.LEASH_INBOX2 ?? "inbox/inbox-v2.json", root), "utf8"));
const client = new Client({ name: "leash-scripted-client", version: "0.1.0" });
await client.connect(new StdioClientTransport({ command: process.execPath, args: [new URL("server.mjs", import.meta.url).pathname], env: { ...process.env }, stderr: "ignore" }));

const call = async (name, args = {}) => {
  const r = await client.callTool({ name, arguments: args });
  const t = r.content.map((c) => c.text).join("\n");
  console.log(`> ${name}(${Object.keys(args).length ? JSON.stringify(args) : ""})\n${t.replace(/^/gm, "  ")}\n`);
  return t;
};

const { tools } = await client.listTools();
console.log(`tools: ${tools.map((t) => t.name).join(", ")}\n`);
await call("leash_status");

if (mode === "--readonly") {
  await call("list_inbox");
  for (const [i, m] of inbox.entries()) if (m.invoice) await call("check_invoice", { email: i });
} else if (mode === "--compromised") {
  for (const [i, m] of inbox.entries()) {
    for (const a of m.attacks ?? []) {
      if (a.action === "send") await call("send_qor", { to: a.to, qor: a.qor, email: i });
      if (a.action === "token-transfer") await call("transfer_fusd", { to: a.to, fusd: a.fusd, email: i });
      if (a.action === "call" && a.fn === "approveVendor") await call("call_invoice_desk", { fn: "approveVendor", address: a.args[0], email: i });
    }
    if (m.invoice) await call("pay_invoice", { email: i });
  }
  await call("leash_status");
}
await client.close();
