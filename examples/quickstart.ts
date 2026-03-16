/**
 * God Clause — Quick Start Example
 *
 * Run: npx ts-node examples/quickstart.ts
 *
 * This demonstrates the core value proposition in 30 lines:
 * 1. Load a PII redaction policy
 * 2. Evaluate an LLM output containing PII
 * 3. Get a "modify" decision with redaction obligations
 * 4. Verify the tamper-evident audit trail
 *
 * No Docker. No sidecars. No config files. Just npm install and run.
 */

import { GodClause } from "../src";

async function main() {
  // 1. Create the governance engine (zero config)
  const gov = new GodClause();

  // 2. Load a trust contract — this YAML is now cryptographically bound to the audit trail
  gov.loadContractYAML(`
    schema_version: "1.0"
    metadata:
      name: PII Safety
      version: "1.0.0"
      author: Platform Team
      description: Redact PII from AI outputs instead of blocking users
      effective_date: "2025-01-01"
    data_governance:
      allowed_input_classes: [public, internal]
      allowed_output_classes: [public]
      retention_period: P90D
      cross_border_transfer: false
    rules:
      - id: PII-001
        description: Redact PII instead of blocking
        action: generate
        conditions:
          - field: output.contains_pii
            operator: equals
            value: false
        on_violation: modify
        obligations:
          - obligation_id: OBL-REDACT
            type: redact_pii
            params: { replacement: "[REDACTED]" }
        tags: [privacy, pii]
  `);

  // 3. Simulate an LLM response that contains PII
  const llmOutput = "John's SSN is 123-45-6789 and his email is john@example.com";

  const decision = await gov.evaluate({
    action: "generate",
    input: { prompt: "Look up John's records" },
    output: { text: llmOutput, contains_pii: true },
    caller: { user_id: "analyst-1", session_id: "sess-1", roles: ["analyst"] },
  });

  // 4. Check the decision
  console.log("Decision outcome:", decision.outcome);      // "modify"
  console.log("Allowed:", decision.allowed);                // true (not blocked)
  console.log("Obligations:", decision.obligations.length); // 1

  if (decision.outcome === "modify") {
    const obligation = decision.obligations[0];
    console.log(`\nObligation: ${obligation.type}`);
    console.log(`Params:`, obligation.params);

    // Your app applies the obligation:
    const replacement = (obligation.params?.replacement as string) ?? "[REDACTED]";
    const cleaned = llmOutput
      .replace(/\d{3}-\d{2}-\d{4}/g, replacement)        // SSNs
      .replace(/[\w.-]+@[\w.-]+\.\w+/g, replacement);     // Emails

    console.log(`\nBefore: "${llmOutput}"`);
    console.log(`After:  "${cleaned}"`);
  }

  // 5. Verify the tamper-evident audit trail
  const { valid } = gov.verifyAuditChain();
  console.log(`\nAudit chain valid: ${valid}`);
  console.log(`Audit entries: ${gov.getAuditEntries().length}`);

  // Every decision is SHA-256 hash-chained. The policy fingerprint
  // (governance_context.policy_sha256) is embedded in each entry.
  // Tampering with any entry breaks the chain.
  const entry = gov.getAuditEntries()[0];
  console.log(`Entry hash: ${entry.hash.substring(0, 16)}...`);
  console.log(`Policy SHA-256: ${entry.policy_sha256?.substring(0, 16)}...`);
}

main().catch(console.error);
