/**
 * God Clause — MCP Agent Governance Demo
 *
 * Shows how to govern autonomous agent tool calls:
 * 1. Load the MCP tool abuse prevention contract
 * 2. Evaluate each tool call with action "mcp_call" and metadata.mcp_tool set to the tool name
 * 3. The contract's mcp_permissions block destructive ops, require approval for writes, rate-limit searches
 * 4. Every decision lands in the tamper-evident audit chain like any other decision
 *
 * This is the zero-trust pattern for agentic AI:
 * Just because an LLM can see a tool doesn't mean it should call it.
 *
 * Run: npx tsx examples/mcp-agent-demo.ts
 */

import { readFileSync } from "fs";
import { join } from "path";
import { GodClause } from "../src";
import type { PolicyDecision } from "../src";

type ToolCall = { tool_name: string; arguments: Record<string, unknown> };

// ─── Formatting helpers ─────────────────────────────────────────────

function label(d: PolicyDecision): string {
  if (!d.allowed) return "\x1b[31m❌ BLOCKED\x1b[0m";
  if (d.outcome === "modify") return "\x1b[33m✋ HUMAN APPROVAL REQUIRED\x1b[0m";
  return "\x1b[32m✅ ALLOWED\x1b[0m";
}

function reason(d: PolicyDecision): string {
  if (!d.allowed) return d.blocks.map((b) => b.rule_description).join("; ");
  if (d.outcome === "modify") return d.obligations.map((o) => `${o.type} (${o.source_rule_id})`).join("; ");
  return "Permitted by matching permission";
}

function banner(title: string): string {
  const line = "═".repeat(44);
  return `${line}\n  ${title}\n${line}\n`;
}

// ─── Main ───────────────────────────────────────────────────────────

async function main() {
  // 1. Load the contract
  const gov = new GodClause();
  const contract = gov.loadContractYAML(readFileSync(join(__dirname, "threats/mcp-tool-abuse.contract.yaml"), "utf-8"));
  console.log(`Loaded contract: ${contract.metadata.name} v${contract.metadata.version}`);
  console.log(`MCP permissions: ${contract.mcp_permissions?.length ?? 0} rules\n`);

  // 2. Every tool call is an ordinary evaluation; the engine applies mcp_permissions and audits it
  const caller = { user_id: "agent-llm-1", session_id: "agent-session-001", roles: ["agent"] };
  const authorize = (call: ToolCall) =>
    gov.evaluate({ action: "mcp_call", input: call.arguments, caller, metadata: { mcp_tool: call.tool_name } });

  // 3. Simulated agent tool calls
  const agentCalls: ToolCall[] = [
    { tool_name: "database.drop_table", arguments: { table: "users" } },
    { tool_name: "database.query", arguments: { sql: "SELECT * FROM users LIMIT 10" } },
    { tool_name: "file_write.config", arguments: { path: "/app/config.yaml", content: "..." } },
    { tool_name: "web_search", arguments: { query: "latest security advisories" } },
    { tool_name: "shell.exec", arguments: { cmd: "rm -rf /tmp/*" } },
    { tool_name: "api.slack.post_message", arguments: { channel: "#general", text: "Hello" } },
    { tool_name: "unknown.dangerous.tool", arguments: {} },
  ];

  console.log(banner("SIMULATED AGENT TOOL CALLS"));
  let allowed = 0;
  let blocked = 0;
  let needsApproval = 0;

  for (const call of agentCalls) {
    const d = await authorize(call);
    console.log(`┌─ Tool: ${call.tool_name}`);
    console.log(`│  Args: ${JSON.stringify(call.arguments)}`);
    console.log(`│  Result: ${label(d)}`);
    console.log(`│  Reason: ${reason(d)}`);
    console.log(`│  Decision: ${d.decision_id}`);
    console.log("└" + "─".repeat(35));
    if (!d.allowed) blocked++;
    else {
      allowed++;
      if (d.outcome === "modify") needsApproval++;
    }
  }

  // 4. Rate limiting: web_search allows 20 calls per session; one was used above
  console.log("\n" + banner("RATE LIMIT DEMO: web_search (limit 20/session)"));
  const search: ToolCall = { tool_name: "web_search", arguments: { query: "search query" } };
  let rateLimitHit = false;
  for (let i = 2; i <= 21; i++) {
    const d = await authorize(search);
    if (!d.allowed) {
      console.log(`  Call #${i}: ${label(d)}`);
      console.log(`  Reason: ${reason(d)}\n`);
      rateLimitHit = true;
      blocked++;
      break;
    }
    if (i <= 3 || i === 20) console.log(`  Call #${i}: ${label(d)}`);
    else if (i === 4) console.log("  ... (calls 4–19 allowed) ...");
  }
  if (!rateLimitHit) console.log("  Rate limit was not reached (unexpected).\n");

  // 5. Summary and audit trail
  console.log(banner("SUMMARY"));
  console.log(`  ✅ Allowed:              ${allowed}`);
  console.log(`  ❌ Blocked:              ${blocked}`);
  console.log(`  ✋ Need human approval:  ${needsApproval}`);

  const entries = gov.getAuditEntries();
  const { valid } = gov.verifyAuditChain();
  console.log(`\n  Audit trail entries:   ${entries.length}`);
  console.log(`  Audit chain valid:    ${valid}`);
  console.log("\nDone. Every tool call was governed and audited.");
}

main().catch(console.error);
