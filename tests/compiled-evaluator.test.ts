import { describe, it, expect } from "vitest";
import { CompiledPolicyEvaluator } from "../src/engine/compiled-evaluator";
import { TrustContract, PolicyRule, PolicyContext, PolicyConditionExpr } from "../src/types";

// ─── Helpers ─────────────────────────────────────────────────────────

function makeContract(rules: PolicyRule[], name = "test-contract", version = "1.0.0"): TrustContract {
  return {
    schema_version: "1.0",
    metadata: {
      name,
      version,
      author: "test",
      description: "test contract",
      effective_date: "2026-01-01",
    },
    data_governance: {
      allowed_input_classes: ["public"],
      allowed_output_classes: ["public"],
      retention_period: "P30D",
      cross_border_transfer: false,
    },
    rules,
  };
}

function makeRule(overrides: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: "R-001",
    description: "Test rule",
    action: "*",
    conditions: [],
    on_violation: "block",
    ...overrides,
  };
}

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "generate",
    input: { prompt: "hello", data_class: "public", score: 0.9 },
    output: { contains_phi: false, confidence: 0.95, text: "world" },
    caller: { user_id: "user-1", session_id: "sess-1", roles: ["admin"] },
    metadata: { env: "test", human_in_loop: true },
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────

describe("CompiledPolicyEvaluator", () => {
  const evaluator = new CompiledPolicyEvaluator();

  // ── Compilation ────────────────────────────────────────────────────

  describe("compilation", () => {
    it("returns a CompiledContract with correct metadata", () => {
      const contract = makeContract([], "my-contract", "2.0.0");
      const compiled = evaluator.compile(contract);
      expect(compiled.contractName).toBe("my-contract");
      expect(compiled.contractVersion).toBe("2.0.0");
      expect(compiled.compiledAt).toBeTruthy();
      expect(typeof compiled.compiledAt).toBe("string");
    });

    it("handles empty rules array", () => {
      const compiled = evaluator.compile(makeContract([]));
      expect(compiled.compiledRules).toHaveLength(0);
    });

    it("compiledRules has same count as original rules", () => {
      const rules = [makeRule({ id: "R-1" }), makeRule({ id: "R-2" }), makeRule({ id: "R-3" })];
      const compiled = evaluator.compile(makeContract(rules));
      expect(compiled.compiledRules).toHaveLength(3);
    });
  });

  // ── Leaf operator evaluation ───────────────────────────────────────

  describe("leaf operator evaluation", () => {
    it("equals operator", () => {
      const rule = makeRule({
        conditions: [{ field: "input.data_class", operator: "equals", value: "public" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      const result = compiled.compiledRules[0].evaluator(makeCtx());
      expect(result.passed).toBe(true);

      const failResult = compiled.compiledRules[0].evaluator(makeCtx({ input: { data_class: "pii" } }));
      expect(failResult.passed).toBe(false);
      expect(failResult.violations[0].field).toBe("input.data_class");
    });

    it("not_equals operator", () => {
      const rule = makeRule({
        conditions: [{ field: "input.data_class", operator: "not_equals", value: "pii" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("contains operator (string)", () => {
      const rule = makeRule({
        conditions: [{ field: "output.text", operator: "contains", value: "wor" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("contains operator (array)", () => {
      const rule = makeRule({
        conditions: [{ field: "caller.roles", operator: "contains", value: "admin" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("not_contains operator", () => {
      const rule = makeRule({
        conditions: [{ field: "output.text", operator: "not_contains", value: "secret" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("greater_than operator", () => {
      const rule = makeRule({
        conditions: [{ field: "output.confidence", operator: "greater_than", value: 0.5 }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);

      const failResult = compiled.compiledRules[0].evaluator(makeCtx({ output: { confidence: 0.3 } }));
      expect(failResult.passed).toBe(false);
    });

    it("less_than operator", () => {
      const rule = makeRule({
        conditions: [{ field: "output.confidence", operator: "less_than", value: 1.0 }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("in operator", () => {
      const rule = makeRule({
        conditions: [{ field: "input.data_class", operator: "in", value: ["public", "internal"] }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("not_in operator", () => {
      const rule = makeRule({
        conditions: [{ field: "input.data_class", operator: "not_in", value: ["pii", "phi"] }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("matches (regex) operator", () => {
      const rule = makeRule({
        conditions: [{ field: "output.text", operator: "matches", value: "^w.*d$" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("exists operator", () => {
      const rule = makeRule({
        conditions: [{ field: "output.text", operator: "exists", value: true }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("not_exists operator", () => {
      const rule = makeRule({
        conditions: [{ field: "output.missing_field", operator: "not_exists", value: true }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });
  });

  // ── Nested conditions ──────────────────────────────────────────────

  describe("nested conditions", () => {
    it("all: AND logic (all must pass)", () => {
      const rule = makeRule({
        conditions: [
          {
            all: [
              { field: "input.data_class", operator: "equals", value: "public" },
              { field: "output.confidence", operator: "greater_than", value: 0.5 },
            ],
          } as PolicyConditionExpr,
        ],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);

      // Fail one condition
      const failResult = compiled.compiledRules[0].evaluator(makeCtx({ output: { confidence: 0.1 } }));
      expect(failResult.passed).toBe(false);
    });

    it("any: OR logic (at least one passes)", () => {
      const rule = makeRule({
        conditions: [
          {
            any: [
              { field: "input.data_class", operator: "equals", value: "pii" },
              { field: "output.confidence", operator: "greater_than", value: 0.5 },
            ],
          } as PolicyConditionExpr,
        ],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      // First condition fails but second passes
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("not: negation", () => {
      const rule = makeRule({
        conditions: [
          {
            not: { field: "output.contains_phi", operator: "equals", value: true },
          } as PolicyConditionExpr,
        ],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      // contains_phi is false, so equals(true) fails, not(fail) passes
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });

    it("deeply nested: any(all(...), not(...))", () => {
      const rule = makeRule({
        conditions: [
          {
            any: [
              {
                all: [
                  { field: "input.data_class", operator: "equals", value: "secret" },
                  { field: "output.confidence", operator: "greater_than", value: 0.99 },
                ],
              },
              {
                not: { field: "output.contains_phi", operator: "equals", value: true },
              },
            ],
          } as PolicyConditionExpr,
        ],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      // First branch (all) fails, second branch (not) passes → any passes
      expect(compiled.compiledRules[0].evaluator(makeCtx()).passed).toBe(true);
    });
  });

  // ── Action matching ────────────────────────────────────────────────

  describe("action matching", () => {
    it("wildcard '*' matches any action", () => {
      const rule = makeRule({ action: "*" });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].actionMatcher("generate")).toBe(true);
      expect(compiled.compiledRules[0].actionMatcher("classify")).toBe(true);
    });

    it("specific action match", () => {
      const rule = makeRule({ action: "generate" });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].actionMatcher("generate")).toBe(true);
      expect(compiled.compiledRules[0].actionMatcher("classify")).toBe(false);
    });

    it("non-matching action auto-passes in evaluate()", async () => {
      const rule = makeRule({
        action: "classify",
        conditions: [{ field: "input.data_class", operator: "equals", value: "impossible" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      const decision = await evaluator.evaluate(compiled, makeCtx({ action: "generate" }));
      // Rule does not match action, so it auto-passes
      expect(decision.evaluations[0].passed).toBe(true);
    });

    it("array of actions", () => {
      const rule = makeRule({ action: ["generate", "summarize"] });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].actionMatcher("generate")).toBe(true);
      expect(compiled.compiledRules[0].actionMatcher("summarize")).toBe(true);
      expect(compiled.compiledRules[0].actionMatcher("translate")).toBe(false);
    });
  });

  // ── Rate limit handling ────────────────────────────────────────────

  describe("rate limit handling", () => {
    it("rules with rate_limit are flagged with hasRateLimit: true", () => {
      const rule = makeRule({
        conditions: [{ field: "caller.user_id", operator: "rate_limit", value: { max: 10, window: "PT1H" } }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      expect(compiled.compiledRules[0].hasRateLimit).toBe(true);
    });

    it("rate limit rules still pass through evaluate (marked as passed placeholder)", async () => {
      const rule = makeRule({
        conditions: [{ field: "caller.user_id", operator: "rate_limit", value: { max: 10, window: "PT1H" } }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      const decision = await evaluator.evaluate(compiled, makeCtx());
      expect(decision.evaluations[0].passed).toBe(true);
    });
  });

  // ── Full evaluation ────────────────────────────────────────────────

  describe("full evaluation", () => {
    it("evaluate() returns PolicyDecision with correct outcome", async () => {
      const rule = makeRule({
        conditions: [{ field: "input.data_class", operator: "equals", value: "public" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      const decision = await evaluator.evaluate(compiled, makeCtx());
      expect(decision.allowed).toBe(true);
      expect(decision.outcome).toBe("permit");
      expect(decision.decision_id).toBeTruthy();
      expect(decision.governance_context).toBeTruthy();
    });

    it("block rules produce deny outcome", async () => {
      const rule = makeRule({
        on_violation: "block",
        conditions: [{ field: "input.data_class", operator: "equals", value: "impossible" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      const decision = await evaluator.evaluate(compiled, makeCtx());
      expect(decision.allowed).toBe(false);
      expect(decision.outcome).toBe("deny");
      expect(decision.blocks).toHaveLength(1);
    });

    it("modify rules produce modify outcome with obligations", async () => {
      const rule = makeRule({
        on_violation: "modify",
        conditions: [{ field: "input.data_class", operator: "equals", value: "impossible" }],
        obligations: [{ obligation_id: "OBL-1", type: "redact", params: { fields: ["ssn"] } }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      const decision = await evaluator.evaluate(compiled, makeCtx());
      expect(decision.allowed).toBe(true);
      expect(decision.outcome).toBe("modify");
      expect(decision.modifications).toHaveLength(1);
      expect(decision.obligations).toHaveLength(1);
      expect(decision.obligations[0].obligation_id).toBe("OBL-1");
    });

    it("tag filtering: includeTags", async () => {
      const rules = [makeRule({ id: "R-1", tags: ["safety"] }), makeRule({ id: "R-2", tags: ["compliance"] })];
      const compiled = evaluator.compile(makeContract(rules));
      const decision = await evaluator.evaluate(compiled, makeCtx(), {
        includeTags: ["safety"],
      });
      expect(decision.evaluations).toHaveLength(1);
      expect(decision.evaluations[0].rule_id).toBe("R-1");
    });

    it("tag filtering: excludeTags", async () => {
      const rules = [makeRule({ id: "R-1", tags: ["safety"] }), makeRule({ id: "R-2", tags: ["compliance"] })];
      const compiled = evaluator.compile(makeContract(rules));
      const decision = await evaluator.evaluate(compiled, makeCtx(), {
        excludeTags: ["safety"],
      });
      expect(decision.evaluations).toHaveLength(1);
      expect(decision.evaluations[0].rule_id).toBe("R-2");
    });
  });

  // ── Benchmark ──────────────────────────────────────────────────────

  describe("benchmark", () => {
    it("benchmark() returns CompilationStats with positive values", () => {
      const rule = makeRule({
        conditions: [{ field: "input.data_class", operator: "equals", value: "public" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      const stats = evaluator.benchmark(compiled, makeCtx(), 100);
      expect(stats.avgEvaluationNs).toBeGreaterThan(0);
      expect(stats.avgInterpretiveNs).toBeGreaterThan(0);
      expect(stats.speedup).toBeGreaterThan(0);
    });

    it("rulesCompiled count matches", () => {
      const rules = [makeRule({ id: "R-1" }), makeRule({ id: "R-2" })];
      const compiled = evaluator.compile(makeContract(rules));
      const stats = evaluator.benchmark(compiled, makeCtx(), 10);
      expect(stats.rulesCompiled).toBe(2);
    });
  });

  // ── Edge cases ─────────────────────────────────────────────────────

  describe("edge cases", () => {
    it("undefined field path returns undefined (causes violation)", () => {
      const rule = makeRule({
        conditions: [{ field: "input.nonexistent.path", operator: "equals", value: "something" }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      const result = compiled.compiledRules[0].evaluator(makeCtx());
      expect(result.passed).toBe(false);
      expect(result.violations[0].actual).toBeUndefined();
    });

    it("deep field path resolution (input.nested.deep.value)", () => {
      const rule = makeRule({
        conditions: [{ field: "input.nested.deep.value", operator: "equals", value: 42 }],
      });
      const compiled = evaluator.compile(makeContract([rule]));
      const ctx = makeCtx({
        input: { nested: { deep: { value: 42 } } },
      });
      const result = compiled.compiledRules[0].evaluator(ctx);
      expect(result.passed).toBe(true);
    });
  });
});
