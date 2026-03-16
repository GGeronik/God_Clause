/**
 * God Clause — Usage Demo
 *
 * Run: npx ts-node examples/demo.ts
 */
import { readFileSync } from "fs";
import { join } from "path";
import { GodClause, PolicyContext } from "../src";

async function main() {
  // ── 1. Initialize the governance framework ──────────────────────
  const gov = new GodClause({
    onBlock: (decision) => {
      console.log(`\n🚫 BLOCKED: ${decision.blocks.map((b) => b.rule_id).join(", ")}`);
    },
    onWarn: (decision) => {
      console.log(`\n⚠️  WARNING: ${decision.warnings.map((w) => w.rule_id).join(", ")}`);
    },
  });

  // ── 2. Load a trust contract from YAML ──────────────────────────
  const contractYAML = readFileSync(
    join(__dirname, "healthcare-ai.contract.yaml"),
    "utf-8",
  );
  const contract = gov.loadContractYAML(contractYAML);
  console.log("Loaded contract:", contract.metadata.name);
  console.log("\n── Plain Language Summary ──");
  console.log(gov.summarize(contract));

  // ── 3. Evaluate a compliant action ──────────────────────────────
  console.log("\n\n══════════════════════════════════════════");
  console.log("TEST 1: Compliant clinical recommendation");
  console.log("══════════════════════════════════════════");

  const compliantCtx: PolicyContext = {
    action: "recommend",
    input: { patient_summary: "..." },
    output: {
      contains_phi: false,
      confidence: 0.92,
      disclaimer_present: true,
    },
    caller: {
      user_id: "dr-smith",
      session_id: "sess-001",
      roles: ["clinician", "attending"],
    },
    metadata: { human_in_loop: true },
  };

  const result1 = await gov.evaluate(compliantCtx);
  console.log(`Decision: ${result1.allowed ? "✅ ALLOWED" : "❌ BLOCKED"}`);
  console.log(`Rules evaluated: ${result1.evaluations.length}`);
  console.log(`Warnings: ${result1.warnings.length}`);
  console.log(`Blocks: ${result1.blocks.length}`);

  // ── 4. Evaluate a non-compliant action ──────────────────────────
  console.log("\n\n══════════════════════════════════════════");
  console.log("TEST 2: Non-compliant — PHI leak + no disclaimer");
  console.log("══════════════════════════════════════════");

  const nonCompliantCtx: PolicyContext = {
    action: "generate",
    input: { prompt: "Summarize patient record" },
    output: {
      contains_phi: true,          // VIOLATION: HC-001
      disclaimer_present: false,   // VIOLATION: HC-004
    },
    caller: {
      user_id: "intern-jones",
      session_id: "sess-002",
      roles: ["intern"],
    },
  };

  const result2 = await gov.evaluate(nonCompliantCtx);
  console.log(`Decision: ${result2.allowed ? "✅ ALLOWED" : "❌ BLOCKED"}`);
  for (const block of result2.blocks) {
    console.log(`  Block: [${block.rule_id}] ${block.rule_description}`);
    for (const v of block.violated_conditions) {
      console.log(`    → ${v.field} ${v.operator} ${JSON.stringify(v.expected)}, got: ${JSON.stringify(v.actual)}`);
    }
  }

  // ── 5. Try enforce() — throws on violation ──────────────────────
  console.log("\n\n══════════════════════════════════════════");
  console.log("TEST 3: enforce() throws on violation");
  console.log("══════════════════════════════════════════");

  try {
    await gov.enforce(nonCompliantCtx);
  } catch (err: any) {
    console.log(`Caught: ${err.name}`);
    console.log(`Message: ${err.message}`);
  }

  // ── 6. Query the audit log ──────────────────────────────────────
  console.log("\n\n══════════════════════════════════════════");
  console.log("AUDIT LOG");
  console.log("══════════════════════════════════════════");

  const entries = gov.getAuditEntries();
  console.log(`Total audit entries: ${entries.length}`);

  for (const entry of entries) {
    console.log(
      `  [${entry.timestamp}] ${entry.action} by ${entry.caller.user_id} — ${entry.allowed ? "ALLOWED" : "BLOCKED"}`,
    );
  }

  // Verify chain integrity
  const integrity = gov.verifyAuditChain();
  console.log(`\nAudit chain integrity: ${integrity.valid ? "✅ VALID" : "❌ BROKEN at entry " + integrity.brokenAt}`);

  // Query blocked actions only
  const blocked = gov.queryAudit({ allowed: false });
  console.log(`Blocked decisions: ${blocked.length}`);
}

main().catch(console.error);
