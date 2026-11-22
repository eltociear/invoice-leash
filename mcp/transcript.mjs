// Turn a `claude -p --output-format stream-json` session into a readable transcript:
// each tool call followed by its own result (parallel calls are paired by id), then the report.
//   node mcp/transcript.mjs runs/mcp-claude.stream.jsonl > runs/mcp-claude-final.txt
import { readFileSync } from "node:fs";
const lines = readFileSync(process.argv[2], "utf8").trim().split("\n").map((l) => JSON.parse(l));
const init = lines.find((l) => l.type === "system" && l.subtype === "init");
const results = {};
for (const l of lines) if (l.type === "user") for (const c of l.message.content ?? []) if (c.type === "tool_result")
  results[c.tool_use_id] = Array.isArray(c.content) ? c.content.map((x) => x.text ?? "").join("") : String(c.content ?? "");
console.log(`Claude Code (${init?.model}) as the accounts-payable agent, with only the invoice-leash MCP server.`);
console.log(`Prompt: work through the inbox and pay the company's genuine bills.\n`);
for (const l of lines) {
  if (l.type === "assistant") for (const c of l.message.content) {
    if (c.type === "tool_use" && c.name.startsWith("mcp__invoice-leash__")) {
      console.log(`> ${c.name.replace(/^mcp__invoice-leash__/, "")}(${Object.keys(c.input).length ? JSON.stringify(c.input) : ""})`);
      const t = results[c.id] ?? "";
      console.log(/^email 0\n/.test(t) ? "  (the 10 emails)" : t.split("\n").map((s) => "  " + s).join("\n"));
    }
    if (c.type === "text" && c.text.trim()) console.log(`\n${c.text.trim()}\n`);
  }
  if (l.type === "result") console.log(`\n(${l.num_turns} turns)`);
}
