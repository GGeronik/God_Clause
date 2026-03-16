import { describe, it, expect, vi } from "vitest";
import {
  GovernedStream,
  createGovernedStream,
  GovernanceEvaluator,
  GovernedStreamOptions,
} from "../src/middleware/streaming";
import type { PolicyContext, PolicyDecision, Obligation } from "../src/types";

// ─── Helpers ─────────────────────────────────────────────────────────

/** Create an async iterable from an array of string chunks. */
async function* chunksFrom(chunks: string[]): AsyncGenerator<string> {
  for (const c of chunks) {
    yield c;
  }
}

/** Collect all yielded values from an async generator. */
async function collect(gen: AsyncGenerator<string>): Promise<string[]> {
  const results: string[] = [];
  for await (const v of gen) {
    results.push(v);
  }
  return results;
}

/** Build a mock governance evaluator that returns configurable decisions. */
function mockGov(
  decisionFn?: (ctx: PolicyContext) => Partial<PolicyDecision>,
): GovernanceEvaluator & { calls: PolicyContext[] } {
  const calls: PolicyContext[] = [];
  return {
    calls,
    async evaluate(ctx: PolicyContext): Promise<PolicyDecision> {
      calls.push(ctx);
      const overrides = decisionFn ? decisionFn(ctx) : {};
      return {
        decision_id: "d-1",
        allowed: true,
        outcome: "permit",
        evaluations: [],
        warnings: [],
        blocks: [],
        logs: [],
        modifications: [],
        obligations: [],
        timestamp: new Date().toISOString(),
        context: ctx,
        ...overrides,
      };
    },
  };
}

const defaultCaller = { user_id: "u1", session_id: "s1", roles: ["user"] };

// ─── Tests ───────────────────────────────────────────────────────────

describe("GovernedStream — sentence boundary mode", () => {
  it("yields governed chunks at sentence boundaries", async () => {
    const gov = mockGov();
    const stream = new GovernedStream({ gov, caller: defaultCaller });

    const source = chunksFrom(["Hello world. ", "How are you? ", "Fine."]);
    const results = await collect(stream.govern(source));

    // "Hello world." and "How are you?" should each be yielded as sentences,
    // "Fine." is flushed at end.
    expect(results).toEqual(["Hello world.", "How are you?", "Fine."]);
  });

  it("handles chunks with no sentence boundaries (buffers until flush)", async () => {
    const gov = mockGov();
    const stream = new GovernedStream({ gov, caller: defaultCaller });

    const source = chunksFrom(["no sentence", " boundary here"]);
    const results = await collect(stream.govern(source));

    // Everything flushed as one chunk at end.
    expect(results).toEqual(["no sentence boundary here"]);
    expect(gov.calls).toHaveLength(1);
  });

  it("single large chunk with multiple sentences yields multiple governed chunks", async () => {
    const gov = mockGov();
    const stream = new GovernedStream({ gov, caller: defaultCaller });

    const source = chunksFrom(["First sentence. Second sentence. Third sentence."]);
    const results = await collect(stream.govern(source));

    // Two complete sentences detected, "Third sentence." flushed at end.
    expect(results).toEqual(["First sentence.", "Second sentence.", "Third sentence."]);
    expect(gov.calls).toHaveLength(3);
  });

  it("handles PII split across chunk boundaries in sentence mode", async () => {
    // SSN "123-45-6789" split across chunks but within same sentence.
    const detectFields = (text: string) => ({
      contains_ssn: /\d{3}-\d{2}-\d{4}/.test(text),
    });
    const applyObligations = (text: string, _obls: Obligation[]) =>
      text.replace(/\d{3}-\d{2}-\d{4}/g, "[REDACTED]");

    const gov = mockGov((ctx) => {
      const output = ctx.output as Record<string, unknown>;
      if (output.contains_ssn) {
        return {
          outcome: "modify" as const,
          obligations: [
            {
              obligation_id: "OBL-1",
              type: "redact_pii",
              params: {},
              source_rule_id: "PII-001",
            },
          ],
        };
      }
      return {};
    });

    const stream = new GovernedStream({
      gov,
      caller: defaultCaller,
      detectFields,
      applyObligations,
    });

    // SSN split across chunks: "123-45-" | "6789" — but they're in the same sentence.
    const source = chunksFrom(["SSN is 123-45-", "6789. Done."]);
    const results = await collect(stream.govern(source));

    // The full sentence "SSN is 123-45-6789." should have SSN detected and redacted.
    expect(results[0]).toBe("SSN is [REDACTED].");
    expect(results[1]).toBe("Done.");
  });
});

describe("GovernedStream — chars boundary mode", () => {
  it("yields governed chunks at char threshold", async () => {
    const gov = mockGov();
    const stream = new GovernedStream({
      gov,
      caller: defaultCaller,
      boundary: "chars",
      charThreshold: 10,
    });

    const source = chunksFrom(["abcdefghij", "klmnopqrst"]);
    const results = await collect(stream.govern(source));

    // With threshold 10 and 20-char overlap capped to buffer size,
    // segments should be produced.
    expect(results.length).toBeGreaterThanOrEqual(1);
    // All text should be present across governed chunks.
    expect(gov.calls.length).toBeGreaterThanOrEqual(1);
  });

  it("handles PII split across chunk boundaries in chars mode with overlap", async () => {
    const detectFields = (text: string) => ({
      contains_ssn: /\d{3}-\d{2}-\d{4}/.test(text),
    });
    const applyObligations = (text: string, _obls: Obligation[]) =>
      text.replace(/\d{3}-\d{2}-\d{4}/g, "[REDACTED]");

    const gov = mockGov((ctx) => {
      const output = ctx.output as Record<string, unknown>;
      if (output.contains_ssn) {
        return {
          outcome: "modify" as const,
          obligations: [
            {
              obligation_id: "OBL-1",
              type: "redact_pii",
              params: {},
              source_rule_id: "PII-001",
            },
          ],
        };
      }
      return {};
    });

    // Use a charThreshold that would split the SSN "123-45-6789" across segments.
    // With the 20-char overlap, the second segment should see the full SSN.
    const stream = new GovernedStream({
      gov,
      caller: defaultCaller,
      boundary: "chars",
      charThreshold: 30,
      detectFields,
      applyObligations,
    });

    // 25 chars + "123-45-6789" (11 chars) = 36 total.
    // First segment: 30 chars (includes "123-45-67" at end).
    // Overlap keeps last 20 chars, so second segment starts with chars that include
    // the full SSN pattern — the overlap ensures the SSN appears in some segment.
    const source = chunksFrom(["Here is the SSN: 123-45-", "6789 done."]);
    const results = await collect(stream.govern(source));

    // At least one segment should have had the SSN detected and redacted.
    const allText = results.join("");
    expect(allText).toContain("[REDACTED]");
  });
});

describe("GovernedStream — edge cases", () => {
  it("flushes remaining buffer on stream end", async () => {
    const gov = mockGov();
    const stream = new GovernedStream({ gov, caller: defaultCaller });

    const source = chunksFrom(["Trailing without period"]);
    const results = await collect(stream.govern(source));

    expect(results).toEqual(["Trailing without period"]);
    expect(gov.calls).toHaveLength(1);
  });

  it("empty stream yields nothing", async () => {
    const gov = mockGov();
    const stream = new GovernedStream({ gov, caller: defaultCaller });

    const source = chunksFrom([]);
    const results = await collect(stream.govern(source));

    expect(results).toEqual([]);
    expect(gov.calls).toHaveLength(0);
  });

  it("skips empty chunks", async () => {
    const gov = mockGov();
    const stream = new GovernedStream({ gov, caller: defaultCaller });

    const source = chunksFrom(["", "Hello. ", "", "World."]);
    const results = await collect(stream.govern(source));

    expect(results).toEqual(["Hello.", "World."]);
    expect(gov.calls).toHaveLength(2);
  });

  it("default options work without detectFields/applyObligations", async () => {
    const gov = mockGov();
    const stream = new GovernedStream({ gov, caller: defaultCaller });

    const source = chunksFrom(["Plain text. No PII here."]);
    const results = await collect(stream.govern(source));

    expect(results).toEqual(["Plain text.", "No PII here."]);
  });

  it("passes correct PolicyContext to gov.evaluate", async () => {
    const gov = mockGov();
    const detectFields = (text: string) => ({ length: text.length });
    const stream = new GovernedStream({
      gov,
      caller: defaultCaller,
      action: "summarize",
      detectFields,
      metadata: { model: "gpt-4" },
    });

    const source = chunksFrom(["Test. "]);
    await collect(stream.govern(source));

    expect(gov.calls).toHaveLength(1);
    const ctx = gov.calls[0];
    expect(ctx.action).toBe("summarize");
    expect(ctx.input).toEqual({});
    expect(ctx.output).toEqual({ text: "Test.", length: 5 });
    expect(ctx.caller).toEqual(defaultCaller);
    expect(ctx.metadata).toEqual({ model: "gpt-4" });
  });
});

describe("createGovernedStream factory", () => {
  it("returns a GovernedStream instance", () => {
    const gov = mockGov();
    const stream = createGovernedStream({ gov, caller: defaultCaller });

    expect(stream).toBeInstanceOf(GovernedStream);
  });
});
