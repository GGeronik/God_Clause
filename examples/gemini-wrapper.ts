/**
 * God Clause — Google Gemini Wrapper Example
 *
 * Shows how to wrap real Gemini calls with governance:
 * 1. User sends prompt
 * 2. God Clause evaluates the input (pre-check)
 * 3. If allowed, call Gemini
 * 4. God Clause evaluates the output (post-check)
 * 5. If modify → apply obligations (redact PII, add disclaimer)
 * 6. Return cleaned response
 *
 * Prerequisites:
 *   npm install @google/generative-ai god-clause
 *   export GEMINI_API_KEY=...
 *
 * Run: npx ts-node examples/gemini-wrapper.ts
 */

import { GodClause } from "../src";

// Simulated Gemini response shape (Google Generative AI SDK)
interface GeminiResponse {
  candidates: Array<{
    content: {
      parts: Array<{ text: string }>;
      role: "model";
    };
    finishReason: "STOP" | "MAX_TOKENS" | "SAFETY";
    safetyRatings: Array<{
      category: string;
      probability: "NEGLIGIBLE" | "LOW" | "MEDIUM" | "HIGH";
    }>;
  }>;
  usageMetadata: {
    promptTokenCount: number;
    candidatesTokenCount: number;
    totalTokenCount: number;
  };
}

// Simulated Gemini call (replace with real Google AI SDK call in production)
async function callLLM(prompt: string): Promise<GeminiResponse> {
  // In production, this would be:
  // const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY!);
  // const model = genAI.getGenerativeModel({ model: "gemini-pro" });
  // const result = await model.generateContent(prompt);
  // const response = result.response;

  void prompt; // Suppress unused parameter warning

  // Simulated response for demo:
  return {
    candidates: [
      {
        content: {
          parts: [
            {
              text: `Based on the records, John Smith's Social Security Number is 123-45-6789.
His email is john.smith@acme.com and phone is (555) 867-5309.
The account balance is $45,230.12.`,
            },
          ],
          role: "model",
        },
        finishReason: "STOP",
        safetyRatings: [
          { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", probability: "NEGLIGIBLE" },
          { category: "HARM_CATEGORY_HATE_SPEECH", probability: "NEGLIGIBLE" },
          { category: "HARM_CATEGORY_HARASSMENT", probability: "LOW" },
          { category: "HARM_CATEGORY_DANGEROUS_CONTENT", probability: "NEGLIGIBLE" },
        ],
      },
    ],
    usageMetadata: {
      promptTokenCount: 12,
      candidatesTokenCount: 48,
      totalTokenCount: 60,
    },
  };
}

// Extract text from Gemini response
function extractText(response: GeminiResponse): string {
  return response.candidates[0].content.parts.map((p) => p.text).join("\n");
}

// Compute a normalized safety score from Gemini's safetyRatings (0.0–1.0)
function computeSafetyScore(
  safetyRatings: GeminiResponse["candidates"][0]["safetyRatings"]
): number {
  const probabilityMap: Record<string, number> = {
    NEGLIGIBLE: 0.0,
    LOW: 0.25,
    MEDIUM: 0.5,
    HIGH: 0.9,
  };
  const scores = safetyRatings.map((r) => probabilityMap[r.probability] ?? 0);
  return scores.length > 0 ? Math.max(...scores) : 0;
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

  // 3. Call Gemini
  const geminiResponse = await callLLM(userPrompt);
  const rawResponse = extractText(geminiResponse);
  console.log(`Raw Gemini response:\n${rawResponse}`);
  console.log("---");

  // 4. Detect PII in the response
  const piiFlags = detectPII(rawResponse);

  // 5. Compute a normalized toxicity score from Gemini's native safetyRatings
  //    This forwards platform-native safety scores into the governance engine,
  //    letting the policy layer use both its own rules and Gemini's built-in signals.
  const geminiSafetyScore = computeSafetyScore(
    geminiResponse.candidates[0].safetyRatings
  );
  console.log(`Gemini safety score (normalized): ${geminiSafetyScore}`);
  console.log(
    `Gemini safety ratings: ${geminiResponse.candidates[0].safetyRatings
      .map((r) => `${r.category}=${r.probability}`)
      .join(", ")}`
  );
  console.log("---");

  // 6. Evaluate against governance contracts
  const decision = await gov.evaluate({
    action: "generate",
    input: { prompt: userPrompt },
    output: {
      text: rawResponse,
      toxicity_score: geminiSafetyScore, // Use Gemini's native safety as toxicity input
      ...piiFlags,
    },
    caller: { user_id: userId, session_id: "sess-1", roles: ["analyst"] },
  });

  console.log(`Decision: ${decision.outcome}`);

  // 7. Handle the decision
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

  // 8. Verify audit trail
  const { valid } = gov.verifyAuditChain();
  const entries = gov.getAuditEntries();
  console.log(`Audit: ${entries.length} entries, chain valid: ${valid}`);
  console.log(`Policy SHA-256: ${entries[0]?.policy_sha256?.substring(0, 32)}...`);
}

main().catch(console.error);
