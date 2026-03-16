import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import {
  GodClause,
  PolicyContext,
  PolicyViolationError,
  parseContract,
  evaluateRule,
  evaluateConditionExpr,
} from "../src";

const healthcareYAML = readFileSync(
  join(__dirname, "../examples/healthcare-ai.contract.yaml"),
  "utf-8",
);

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "recommend",
    input: { prompt: "test" },
    output: {
      contains_phi: false,
      confidence: 0.92,
      disclaimer_present: true,
    },
    caller: {
      user_id: "dr-test",
      session_id: "sess-test",
      roles: ["clinician"],
    },
    metadata: { human_in_loop: true },
    ...overrides,
  };
}

describe("Policy Engine", () => {
  it("allows a fully compliant context", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    const decision = await gov.evaluate(makeCtx());
    expect(decision.allowed).toBe(true);
    expect(decision.blocks).toHaveLength(0);
  });

  it("blocks when PHI leaks in output", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    const decision = await gov.evaluate(
      makeCtx({
        action: "generate",
        output: { contains_phi: true, disclaimer_present: true },
      }),
    );
    expect(decision.allowed).toBe(false);
    expect(decision.blocks.some((b) => b.rule_id === "HC-001")).toBe(true);
  });

  it("blocks clinical decisions without human-in-the-loop", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    const decision = await gov.evaluate(
      makeCtx({
        action: "decide",
        metadata: { human_in_loop: false },
      }),
    );
    expect(decision.allowed).toBe(false);
    expect(decision.blocks.some((b) => b.rule_id === "HC-002")).toBe(true);
  });

  it("warns when confidence is below threshold", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    const decision = await gov.evaluate(
      makeCtx({
        output: {
          contains_phi: false,
          confidence: 0.5,
          disclaimer_present: true,
        },
      }),
    );
    expect(decision.allowed).toBe(true);
    expect(decision.warnings.some((w) => w.rule_id === "HC-003")).toBe(true);
  });

  it("enforce() throws PolicyViolationError on block", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await expect(
      gov.enforce(
        makeCtx({
          action: "generate",
          output: { contains_phi: true, disclaimer_present: false },
        }),
      ),
    ).rejects.toThrow(PolicyViolationError);
  });

  it("enforce() resolves for compliant context", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    const decision = await gov.enforce(makeCtx());
    expect(decision.allowed).toBe(true);
  });

  it("blocks non-clinician callers from clinical actions", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    const decision = await gov.evaluate(
      makeCtx({
        caller: {
          user_id: "admin-bob",
          session_id: "sess-x",
          roles: ["admin"],
        },
      }),
    );
    expect(decision.allowed).toBe(false);
    expect(decision.blocks.some((b) => b.rule_id === "HC-005")).toBe(true);
  });

  it("populates logs array for log-severity violations", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(`
schema_version: "1.0"
metadata:
  name: Log Test
  version: "1.0.0"
  author: Test
  description: Test log severity
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: LOG-001
    description: Log when input is long
    action: "*"
    conditions:
      - field: input.token_count
        operator: less_than
        value: 100
    on_violation: log
`);

    const decision = await gov.evaluate(
      makeCtx({ input: { prompt: "test", token_count: 500 } }),
    );
    expect(decision.allowed).toBe(true);
    expect(decision.logs).toHaveLength(1);
    expect(decision.logs[0].rule_id).toBe("LOG-001");
  });

  it("fires onLog hook for log-severity violations", async () => {
    let hookFired = false;
    const gov = new GodClause({
      onLog: () => { hookFired = true; },
    });
    gov.loadContractYAML(`
schema_version: "1.0"
metadata:
  name: Hook Test
  version: "1.0.0"
  author: Test
  description: Test
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: LOG-H1
    description: Log hook test
    action: "*"
    conditions:
      - field: input.x
        operator: equals
        value: 1
    on_violation: log
`);

    await gov.evaluate(makeCtx({ input: { x: 999 } }));
    expect(hookFired).toBe(true);
  });
});

describe("Rule Evaluator", () => {
  it("evaluates individual rules correctly", async () => {
    const contract = parseContract(healthcareYAML);
    const rule = contract.rules.find((r) => r.id === "HC-001")!;

    const ctx = makeCtx({
      output: { contains_phi: false, confidence: 0.9, disclaimer_present: true },
    });
    const result = await evaluateRule(rule, ctx);
    expect(result.passed).toBe(true);
  });

  it("skips rules that don't match the action", async () => {
    const contract = parseContract(healthcareYAML);
    const rule = contract.rules.find((r) => r.id === "HC-002")!;

    const ctx = makeCtx({ action: "generate" });
    const result = await evaluateRule(rule, ctx);
    expect(result.passed).toBe(true);
  });
});

describe("Composite Condition Evaluator", () => {
  const ctx = makeCtx({
    output: { confidence: 0.92, flagged: false, contains_phi: false, disclaimer_present: true },
    caller: { user_id: "u1", session_id: "s1", roles: ["admin", "clinician"] },
  });

  it("evaluates ANY (at least one must pass)", () => {
    const result = evaluateConditionExpr({
      any: [
        { field: "caller.roles", operator: "contains", value: "admin" },
        { field: "caller.roles", operator: "contains", value: "superuser" },
      ],
    }, ctx);
    expect(result.passed).toBe(true);
  });

  it("fails ANY when none pass", () => {
    const result = evaluateConditionExpr({
      any: [
        { field: "caller.roles", operator: "contains", value: "superuser" },
        { field: "caller.roles", operator: "contains", value: "root" },
      ],
    }, ctx);
    expect(result.passed).toBe(false);
    expect(result.violations.length).toBe(2);
  });

  it("evaluates ALL (all must pass)", () => {
    const result = evaluateConditionExpr({
      all: [
        { field: "output.confidence", operator: "greater_than", value: 0.9 },
        { field: "output.flagged", operator: "equals", value: false },
      ],
    }, ctx);
    expect(result.passed).toBe(true);
  });

  it("fails ALL when any child fails", () => {
    const result = evaluateConditionExpr({
      all: [
        { field: "output.confidence", operator: "greater_than", value: 0.99 },
        { field: "output.flagged", operator: "equals", value: false },
      ],
    }, ctx);
    expect(result.passed).toBe(false);
  });

  it("evaluates NOT (inverts child)", () => {
    const result = evaluateConditionExpr({
      not: { field: "output.flagged", operator: "equals", value: true },
    }, ctx);
    expect(result.passed).toBe(true);
  });

  it("fails NOT when child passes", () => {
    const result = evaluateConditionExpr({
      not: { field: "output.flagged", operator: "equals", value: false },
    }, ctx);
    expect(result.passed).toBe(false);
  });

  it("handles nested composites (ANY containing ALL with NOT)", () => {
    const result = evaluateConditionExpr({
      any: [
        { field: "caller.roles", operator: "contains", value: "superuser" },
        {
          all: [
            { field: "output.confidence", operator: "greater_than", value: 0.9 },
            { not: { field: "output.flagged", operator: "equals", value: true } },
          ],
        },
      ],
    }, ctx);
    expect(result.passed).toBe(true);
  });

  it("integrates composite conditions in full rule evaluation", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(`
schema_version: "1.0"
metadata:
  name: Composite Integration
  version: "1.0.0"
  author: Test
  description: Test
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: COMP-INT-001
    description: Must be admin OR high confidence
    action: generate
    conditions:
      - any:
          - field: caller.roles
            operator: contains
            value: admin
          - field: output.confidence
            operator: greater_than
            value: 0.95
    on_violation: block
`);

    const d1 = await gov.evaluate({
      action: "generate",
      input: {},
      output: { confidence: 0.5 },
      caller: { user_id: "u1", session_id: "s1", roles: ["admin"] },
    });
    expect(d1.allowed).toBe(true);

    const d2 = await gov.evaluate({
      action: "generate",
      input: {},
      output: { confidence: 0.99 },
      caller: { user_id: "u2", session_id: "s2", roles: ["viewer"] },
    });
    expect(d2.allowed).toBe(true);

    const d3 = await gov.evaluate({
      action: "generate",
      input: {},
      output: { confidence: 0.5 },
      caller: { user_id: "u3", session_id: "s3", roles: ["viewer"] },
    });
    expect(d3.allowed).toBe(false);
  });
});
