import { describe, it, expect } from "vitest";
import { lintContract } from "../src/cli/linter";
import type { TrustContract, PolicyRule } from "../src/types";

function makeContract(overrides: Partial<TrustContract> = {}): TrustContract {
  return {
    schema_version: "1.0",
    metadata: {
      name: "Lint Test",
      version: "1.0.0",
      author: "Test",
      description: "Test contract",
      effective_date: "2025-01-01",
      review_date: "2025-06-01",
      stakeholders: ["Test Team"],
    },
    data_governance: {
      allowed_input_classes: ["public"],
      allowed_output_classes: ["public"],
      retention_period: "P30D",
      cross_border_transfer: false,
    },
    rules: [],
    ...overrides,
  };
}

function makeRule(overrides: Partial<PolicyRule> = {}): PolicyRule {
  return {
    id: "TEST-001",
    description: "Test rule",
    action: "generate",
    conditions: [{ field: "output.safe", operator: "equals", value: true }],
    on_violation: "block",
    tags: ["test"],
    ...overrides,
  };
}

describe("Extended Linter Rules", () => {
  describe("rule-shadowed", () => {
    it("warns when a non-block rule follows a wildcard block rule", () => {
      const contract = makeContract({
        rules: [
          makeRule({ id: "R-1", action: "*", on_violation: "block" }),
          makeRule({ id: "R-2", action: "generate", on_violation: "warn" }),
        ],
      });

      const results = lintContract(contract);
      const shadowed = results.find((r) => r.rule === "rule-shadowed");
      expect(shadowed).toBeDefined();
      expect(shadowed!.ruleId).toBe("R-2");
    });

    it("does not warn when block rules are not overlapping", () => {
      const contract = makeContract({
        rules: [
          makeRule({ id: "R-1", action: "classify", on_violation: "block" }),
          makeRule({ id: "R-2", action: "generate", on_violation: "warn" }),
        ],
      });

      const results = lintContract(contract);
      const shadowed = results.find((r) => r.rule === "rule-shadowed");
      expect(shadowed).toBeUndefined();
    });
  });

  describe("missing-deny-for-hazard", () => {
    it("warns when hazard class has no block rule", () => {
      const contract = makeContract({
        rules: [makeRule({ id: "R-1", hazard_class: "pii_exposure", on_violation: "warn" })],
      });

      const results = lintContract(contract);
      const missing = results.find((r) => r.rule === "missing-deny-for-hazard");
      expect(missing).toBeDefined();
      expect(missing!.message).toContain("pii_exposure");
    });

    it("does not warn when hazard class has a block rule", () => {
      const contract = makeContract({
        rules: [makeRule({ id: "R-1", hazard_class: "pii_exposure", on_violation: "block" })],
      });

      const results = lintContract(contract);
      const missing = results.find((r) => r.rule === "missing-deny-for-hazard");
      expect(missing).toBeUndefined();
    });
  });

  describe("model-binding-unused", () => {
    it("warns when model bindings defined but no rules reference models", () => {
      const contract = makeContract({
        model_bindings: [{ model_id: "gpt-4", provider: "openai" }],
        rules: [makeRule()],
      });

      const results = lintContract(contract);
      const unused = results.find((r) => r.rule === "model-binding-unused");
      expect(unused).toBeDefined();
    });

    it("does not warn when rules reference model metadata", () => {
      const contract = makeContract({
        model_bindings: [{ model_id: "gpt-4", provider: "openai" }],
        rules: [
          makeRule({
            id: "R-1",
            conditions: [{ field: "metadata.model_id", operator: "in", value: ["gpt-4"] }],
          }),
        ],
      });

      const results = lintContract(contract);
      const unused = results.find((r) => r.rule === "model-binding-unused");
      expect(unused).toBeUndefined();
    });
  });

  describe("mcp-permission-overlap", () => {
    it("warns when MCP permissions have overlapping patterns", () => {
      const contract = makeContract({
        mcp_permissions: [
          { tool_pattern: "file_*", allowed: true },
          { tool_pattern: "file_read", allowed: false },
        ],
        rules: [makeRule()],
      });

      const results = lintContract(contract);
      const overlap = results.find((r) => r.rule === "mcp-permission-overlap");
      expect(overlap).toBeDefined();
    });

    it("does not warn with non-overlapping patterns", () => {
      const contract = makeContract({
        mcp_permissions: [
          { tool_pattern: "file_*", allowed: true },
          { tool_pattern: "database_*", allowed: false },
        ],
        rules: [makeRule()],
      });

      const results = lintContract(contract);
      const overlap = results.find((r) => r.rule === "mcp-permission-overlap");
      expect(overlap).toBeUndefined();
    });
  });

  describe("obligation-without-handler", () => {
    it("warns on non-standard obligation types", () => {
      const contract = makeContract({
        rules: [
          makeRule({
            id: "R-1",
            on_violation: "modify",
            obligations: [{ obligation_id: "OBL-1", type: "custom_exotic_handler" }],
          }),
        ],
      });

      const results = lintContract(contract);
      const nonStandard = results.find((r) => r.rule === "obligation-without-handler");
      expect(nonStandard).toBeDefined();
      expect(nonStandard!.message).toContain("custom_exotic_handler");
    });

    it("does not warn on standard obligation types", () => {
      const contract = makeContract({
        rules: [
          makeRule({
            id: "R-1",
            on_violation: "modify",
            obligations: [{ obligation_id: "OBL-1", type: "redact_pii" }],
          }),
        ],
      });

      const results = lintContract(contract);
      const nonStandard = results.find((r) => r.rule === "obligation-without-handler");
      expect(nonStandard).toBeUndefined();
    });
  });

  describe("missing-required-evidence", () => {
    it("warns when human_review evidence is required but no review obligation exists", () => {
      const contract = makeContract({
        rules: [
          makeRule({
            id: "R-1",
            on_violation: "block",
            required_evidence: ["human_review"],
          }),
        ],
      });

      const results = lintContract(contract);
      const missing = results.find((r) => r.rule === "missing-required-evidence");
      expect(missing).toBeDefined();
    });

    it("does not warn when human_review evidence matches a modify + require_review rule", () => {
      const contract = makeContract({
        rules: [
          makeRule({
            id: "R-1",
            on_violation: "modify",
            required_evidence: ["human_review"],
            obligations: [{ obligation_id: "OBL-1", type: "require_review" }],
          }),
        ],
      });

      const results = lintContract(contract);
      const missing = results.find((r) => r.rule === "missing-required-evidence");
      expect(missing).toBeUndefined();
    });
  });

  describe("rule-unreachable", () => {
    it("warns on conflicting equals + not_equals conditions", () => {
      const contract = makeContract({
        rules: [
          makeRule({
            id: "R-1",
            conditions: [
              { field: "output.safe", operator: "equals", value: true },
              { field: "output.safe", operator: "not_equals", value: true },
            ],
          }),
        ],
      });

      const results = lintContract(contract);
      const unreachable = results.find((r) => r.rule === "rule-unreachable");
      expect(unreachable).toBeDefined();
      expect(unreachable!.ruleId).toBe("R-1");
    });

    it("warns on impossible numeric range (greater_than >= less_than)", () => {
      const contract = makeContract({
        rules: [
          makeRule({
            id: "R-1",
            conditions: [
              { field: "output.score", operator: "greater_than", value: 10 },
              { field: "output.score", operator: "less_than", value: 5 },
            ],
          }),
        ],
      });

      const results = lintContract(contract);
      const unreachable = results.find((r) => r.rule === "rule-unreachable");
      expect(unreachable).toBeDefined();
    });

    it("does not warn on valid numeric range", () => {
      const contract = makeContract({
        rules: [
          makeRule({
            id: "R-1",
            conditions: [
              { field: "output.score", operator: "greater_than", value: 5 },
              { field: "output.score", operator: "less_than", value: 10 },
            ],
          }),
        ],
      });

      const results = lintContract(contract);
      const unreachable = results.find((r) => r.rule === "rule-unreachable");
      expect(unreachable).toBeUndefined();
    });
  });
});
