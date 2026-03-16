import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { GodClause, PolicyContext } from "../src";

const compositeYAML = readFileSync(
  join(__dirname, "../examples/composite-policy.contract.yaml"),
  "utf-8",
);

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "decide",
    input: {},
    caller: { user_id: "u1", session_id: "s1", roles: ["senior_analyst"] },
    metadata: {},
    ...overrides,
  };
}

describe("Tag Filtering", () => {
  it("includeTags only evaluates matching rules", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(compositeYAML);

    // Only evaluate rules tagged "fairness"
    const decision = await gov.evaluate(
      makeCtx({ action: "recommend", output: { bias_flag: true, confidence: 0.9 } }),
      { includeTags: ["fairness"] },
    );
    // FIN-002 has tags [fairness, quality] and should block
    expect(decision.allowed).toBe(false);
    expect(decision.blocks.some((b) => b.rule_id === "FIN-002")).toBe(true);
    // FIN-001 (access-control) should not be evaluated
    expect(decision.evaluations.every((e) => e.rule_id !== "FIN-001")).toBe(true);
  });

  it("excludeTags skips matching rules", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(compositeYAML);

    // Exclude audit tag — FIN-004 should be skipped
    const decision = await gov.evaluate(
      makeCtx({ action: "classify", input: { amount: 2000000 } }),
      { excludeTags: ["audit"] },
    );
    expect(decision.evaluations.every((e) => e.rule_id !== "FIN-004")).toBe(true);
  });

  it("combined include and exclude", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(compositeYAML);

    // Include traceability but exclude model-governance
    const decision = await gov.evaluate(
      makeCtx({ action: "classify" }),
      { includeTags: ["traceability"], excludeTags: ["model-governance"] },
    );
    // FIN-003 has both traceability and model-governance — exclude wins
    expect(decision.evaluations).toHaveLength(0);
  });

  it("no filter evaluates all rules", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(compositeYAML);

    const decision = await gov.evaluate(makeCtx());
    expect(decision.evaluations.length).toBeGreaterThan(0);
  });

  it("records tags in audit entries", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(compositeYAML);

    await gov.evaluate(makeCtx());
    const entries = gov.getAuditEntries();
    expect(entries[0].tags).toBeDefined();
    expect(entries[0].tags!.length).toBeGreaterThan(0);
  });

  it("queries audit by tags", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(compositeYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx({ action: "recommend", output: { bias_flag: false, confidence: 0.9 } }));

    const fairnessEntries = gov.queryAudit({ tags: ["fairness"] });
    // The second evaluation against "recommend" action would match rules with fairness tag
    expect(fairnessEntries.length).toBeGreaterThan(0);
  });
});

describe("Governance Context", () => {
  it("attaches governance context to decisions", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(compositeYAML);

    const decision = await gov.evaluate(makeCtx());
    expect(decision.governance_context).toBeDefined();
    expect(decision.governance_context!.contract_id).toContain("Financial AI Governance");
    expect(decision.governance_context!.policy_sha256).toBeDefined();
    expect(decision.governance_context!.policy_sha256.length).toBe(64);
  });

  it("policy_sha256 is consistent for same rules", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(compositeYAML);

    const d1 = await gov.evaluate(makeCtx());
    const d2 = await gov.evaluate(makeCtx());
    expect(d1.governance_context!.policy_sha256).toBe(d2.governance_context!.policy_sha256);
  });

  it("policy_sha256 changes when rules change", async () => {
    const gov1 = new GodClause();
    gov1.loadContractYAML(compositeYAML);
    const d1 = await gov1.evaluate(makeCtx());

    const gov2 = new GodClause();
    gov2.loadContractYAML(`
schema_version: "1.0"
metadata:
  name: Different Rules
  version: "1.0.0"
  author: Test
  description: Different rules
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: D-001
    description: Different
    action: "*"
    conditions:
      - field: input.x
        operator: exists
        value: true
    on_violation: warn
`);
    const d2 = await gov2.evaluate(makeCtx());
    expect(d1.governance_context!.policy_sha256).not.toBe(d2.governance_context!.policy_sha256);
  });

  it("records policy_sha256 in audit entries", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(compositeYAML);

    await gov.evaluate(makeCtx());
    const entries = gov.getAuditEntries();
    expect(entries[0].policy_sha256).toBeDefined();
    expect(entries[0].policy_sha256!.length).toBe(64);
  });
});
