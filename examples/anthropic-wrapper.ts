/**
 * God Clause — Anthropic (Claude) Wrapper Example
 *
 * Shows how to wrap real Claude calls with governance:
 * 1. User sends prompt
 * 2. God Clause evaluates the input (pre-check)
 * 3. If allowed, call Claude (Anthropic Messages API)
 * 4. God Clause evaluates the output (post-check)
 * 5. If modify → apply obligations (redact PII, add disclaimer)
 * 6. Return cleaned response
 *
 * Prerequisites:
 *   npm install @anthropic-ai/sdk god-clause
 *   export ANTHROPIC_API_KEY=sk-ant-...
 *
 * Run: npx ts-node examples/anthropic-wrapper.ts
 */

import { GodClause } from "../src";

// Anthropic Messages API response shape
interface AnthropicMessage {
  id: string;
  type: "message";
  role: "assistant";
  content: Array<{ type: "text"; text: string }>;
  model: string;
  stop_reason: "end_turn" | "max_tokens" | "stop_sequence";
  usage: { input_tokens: number; output_tokens: number };
}

// Simulated Anthropic Messages API response (replace with real Anthropic SDK call in production)
async function callLLM(prompt: string): Promise<AnthropicMessage> {
  // In production, this would be:
  // const anthropic = new Anthropic();
  // const message = await anthropic.messages.create({
  //   model: "claude-sonnet-4-20250514",
  //   max_tokens: 1024,
  //   messages: [{ role: "user", content: prompt }],
  // });

  // Simulated response for demo:
  void prompt;
  return {
    id: "msg_01XFDUDYJgAACzvnptvVoYEL",
    type: "message",
    role: "assistant",
    content: [
      {
        type: "text",
        text: `Based on the records, John Smith's Social Security Number is 123-45-6789.
His email is john.smith@acme.com and phone is (555) 867-5309.
The account balance is $45,230.12.`,
      },
    ],
    model: "claude-sonnet-4-20250514",
    stop_reason: "end_turn",
    usage: { input_tokens: 25, output_tokens: 62 },
  };
}

// Simple PII detector (in production, use a proper NER model or regex library)
function detectPII(text: string): {
  contains_pii: boolean;
  contains_ssn: boolean;
  contains_email: boolean;
  contains_phone: boolean;
} {
  return {
    contains_pii:
      /\d{3}-\d{2}-\d{4}/.test(text) ||
      /[\w.-]+@[\w.-]+\.\w+/.test(text) ||
      /\(\d{3}\)\s?\d{3}-\d{4}/.test(text),
    contains_ssn: /\d{3}-\d{2}-\d{4}/.test(text),
    contains_email: /[\w.-]+@[\w.-]+\.\w+/.test(text),
    contains_phone: /\(\d{3}\)\s?\d{3}-\d{4}/.test(text),
  };
}

// Apply redaction obligations to text
function applyRedaction(text: string, replacement: string): string {
  return text
    .replace(/\d{3}-\d{2}-\d{4}/g, replacement)           // SSNs
    .replace(/[\w.-]+@[\w.-]+\.\w+/g, replacement)        // Emails
    .replace(/\(\d{3}\)\s?\d{3}-\d{4}/g, replacement);    // Phone numbers
}

async function main() {
  // 1. Set up governance
  const gov = new GodClause();

  gov.loadContractYAML(`
    schema_version: "1.0"
    metadata:
      name: LLM Output Safety
      version: "1.0.0"
      author: Platform Team
      description: PII redaction and safety guardrails for LLM outputs
      effective_date: "2025-01-01"
    data_governance:
      allowed_input_classes: [public, internal]
      allowed_output_classes: [public]
      retention_period: P90D
      cross_border_transfer: false
    rules:
      - id: PII-001
        description: Redact PII from AI outputs
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
      - id: PII-002
        description: Block SSN exposure entirely
        action: generate
        conditions:
          - field: output.contains_ssn
            operator: equals
            value: false
        on_violation: block
        message: "SSN detected in output — blocked for safety"
        tags: [privacy, pii, critical]
      - id: SAFETY-001
        description: Block toxic content
        action: generate
        conditions:
          - field: output.toxicity_score
            operator: less_than
            value: 0.7
        on_violation: block
        tags: [safety, content]
  `);

  // 2. Incoming user request
  const userPrompt = "What are John Smith's account details?";
  const userId = "analyst-42";

  console.log(`User prompt: "${userPrompt}"`);
  console.log("---");

  // 3. Call the LLM
  const response = await callLLM(userPrompt);
  const rawResponse = response.content.filter(b => b.type === "text").map(b => b.text).join("\n");
  console.log(`Raw LLM response:\n${rawResponse}`);
  console.log("---");

  // 4. Detect PII in the response
  const piiFlags = detectPII(rawResponse);

  // 5. Evaluate against governance contracts
  const decision = await gov.evaluate({
    action: "generate",
    input: { prompt: userPrompt },
    output: {
      text: rawResponse,
      toxicity_score: 0.05, // Low toxicity
      ...piiFlags,
    },
    caller: { user_id: userId, session_id: "sess-1", roles: ["analyst"] },
  });

  console.log(`Decision: ${decision.outcome}`);

  // 6. Handle the decision
  if (decision.outcome === "deny") {
    console.log(`BLOCKED: ${decision.blocks.map((b) => b.rule_description).join(", ")}`);
    console.log("Response to user: Sorry, I can't provide that information.");
    return;
  }

  let finalResponse = rawResponse;

  if (decision.outcome === "modify") {
    console.log(`Obligations: ${decision.obligations.map((o) => o.type).join(", ")}`);

    for (const obligation of decision.obligations) {
      if (obligation.type === "redact_pii") {
        const replacement = (obligation.params?.replacement as string) ?? "[REDACTED]";
        finalResponse = applyRedaction(finalResponse, replacement);
      }
    }
  }

  if (decision.warnings.length > 0) {
    console.log(`Warnings: ${decision.warnings.map((w) => w.rule_description).join(", ")}`);
  }

  console.log(`\nFinal response to user:\n${finalResponse}`);
  console.log("---");

  // 7. Verify audit trail
  const { valid } = gov.verifyAuditChain();
  const entries = gov.getAuditEntries();
  console.log(`Audit: ${entries.length} entries, chain valid: ${valid}`);
  console.log(`Policy SHA-256: ${entries[0]?.policy_sha256?.substring(0, 32)}...`);
}

main().catch(console.error);
