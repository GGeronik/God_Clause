/**
 * God Clause — MCP Agent Governance Demo
 *
 * Shows how to intercept and govern autonomous agent tool calls:
 * 1. Load the MCP tool abuse prevention contract
 * 2. Create an MCPRouter from the contract's mcp_permissions
 * 3. Simulate an LLM agent attempting various tool calls
 * 4. MCPRouter blocks destructive ops, requires approval for writes, rate-limits searches
 * 5. Every decision is logged to the tamper-evident audit trail
 *
 * This is the zero-trust pattern for agentic AI:
 * Just because an LLM can see a tool doesn't mean it should call it.
 *
 * Run: npx ts-node examples/mcp-agent-demo.ts
 */

import { readFileSync } from "fs";
import { join } from "path";
import { GodClause, MCPRouter, MemoryStateStore } from "../src";
import type { MCPToolCall, MCPAuthResult, PolicyContext } from "../src";

// ─── Formatting helpers ─────────────────────────────────────────────

function resultLabel(result: MCPAuthResult): string {
  if (!result.allowed) return "\x1b[31m\u274C BLOCKED\x1b[0m";
  if (result.require_human_approval) return "\x1b[33m\u270B HUMAN APPROVAL REQUIRED\x1b[0m";
  return "\x1b[32m\u2705 ALLOWED\x1b[0m";
}

function printResult(call: MCPToolCall, result: MCPAuthResult): void {
  const reason = result.denial_reason
    ? result.denial_reason
    : result.require_human_approval
      ? "Permission requires human approval before execution"
      : "Permitted by matching rule";

  console.log(`\u250C\u2500 Tool: ${call.tool_name}`);
  console.log(`\u2502  Args: ${JSON.stringify(call.arguments)}`);
  console.log(`\u2502  Result: ${resultLabel(result)}`);
  console.log(`\u2502  Reason: ${reason}`);
  console.log(`\u2502  Audit: ${result.audit_level}`);
  console.log(`\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500`);
}

// ─── Main ───────────────────────────────────────────────────────────

async function main() {
  // 1. Load the MCP tool abuse prevention contract from file
  const gov = new GodClause();
  const yaml = readFileSync(
    join(__dirname, "threats/mcp-tool-abuse.contract.yaml"),
    "utf-8",
  );
  const contract = gov.loadContractYAML(yaml);
  console.log(`Loaded contract: ${contract.metadata.name} v${contract.metadata.version}`);
  console.log(`MCP permissions: ${contract.mcp_permissions?.length ?? 0} rules\n`);

  // 2. Create an MCPRouter from the contract's mcp_permissions
  const stateStore = new MemoryStateStore();
  const router = new MCPRouter(contract.mcp_permissions ?? [], stateStore);

  // 3. Define simulated agent tool calls
  const sessionId = "agent-session-001";

  const agentCalls: MCPToolCall[] = [
    { tool_name: "database.drop_table", arguments: { table: "users" }, session_id: sessionId },
    { tool_name: "database.query", arguments: { sql: "SELECT * FROM users LIMIT 10" }, session_id: sessionId },
    { tool_name: "file_write.config", arguments: { path: "/app/config.yaml", content: "..." }, session_id: sessionId },
    { tool_name: "web_search", arguments: { query: "latest security advisories" }, session_id: sessionId },
    { tool_name: "shell.exec", arguments: { cmd: "rm -rf /tmp/*" }, session_id: sessionId },
    { tool_name: "api.slack.post_message", arguments: { channel: "#general", text: "Hello" }, session_id: sessionId },
    { tool_name: "unknown.dangerous.tool", arguments: {}, session_id: sessionId },
  ];

  // 4. Shared policy context for authorization
  const ctx: PolicyContext = {
    action: "tool_call" as const,
    input: {},
    caller: {
      user_id: "agent-llm-1",
      session_id: sessionId,
      roles: ["agent"],
    },
  };

  // 5. Evaluate each tool call
  console.log("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550");
  console.log("  SIMULATED AGENT TOOL CALLS");
  console.log("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n");

  let allowed = 0;
  let blocked = 0;
  let needsApproval = 0;

  for (const call of agentCalls) {
    const result = await router.authorize(call, ctx);
    printResult(call, result);

    if (!result.allowed) blocked++;
    else if (result.require_human_approval) { needsApproval++; allowed++; }
    else allowed++;
  }

  // 6. Demonstrate rate limiting with web_search
  console.log("\n\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550");
  console.log("  RATE LIMIT DEMO: web_search (limit 20/session)");
  console.log("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n");

  // We already called web_search once above, so we need 19 more to hit the limit,
  // then call #21 should be blocked.
  const searchCall: MCPToolCall = {
    tool_name: "web_search",
    arguments: { query: "search query" },
    session_id: sessionId,
  };

  let rateLimitHit = false;
  for (let i = 2; i <= 21; i++) {
    const result = await router.authorize(searchCall, ctx);
    if (!result.allowed) {
      console.log(`  Call #${i}: ${resultLabel(result)}`);
      console.log(`  Reason: ${result.denial_reason}\n`);
      rateLimitHit = true;
      blocked++;
      break;
    }
    if (i <= 3 || i === 20) {
      console.log(`  Call #${i}: ${resultLabel(result)}`);
    } else if (i === 4) {
      console.log("  ... (calls 4\u201319 allowed) ...");
    }
  }

  if (!rateLimitHit) {
    console.log("  Rate limit was not reached (unexpected).\n");
  }

  // 7. Print summary
  console.log("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550");
  console.log("  SUMMARY");
  console.log("\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n");
  console.log(`  \u2705 Allowed:              ${allowed}`);
  console.log(`  \u274C Blocked:              ${blocked}`);
  console.log(`  \u270B Need human approval:  ${needsApproval}`);

  // 8. Show audit trail from governance evaluations
  const auditEntries = gov.getAuditEntries();
  const { valid } = gov.verifyAuditChain();
  console.log(`\n  Audit trail entries:   ${auditEntries.length}`);
  console.log(`  Audit chain valid:    ${valid}`);
  console.log("\nDone. Every tool call was governed. No unaudited actions.");
}

main().catch(console.error);
