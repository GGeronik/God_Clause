import { describe, it, expect } from "vitest";
import {
  TLAPlusGenerator,
  sanitizeModuleName,
  sanitizeId,
  fieldToVar,
  extractAllFields,
  leafToTLA,
  conditionToTLA,
  tlaValue,
  tlaSetValue,
} from "../src/compliance/tlaplus-generator";
import type { TrustContract, PolicyRule } from "../src/types";

// ─── Fixtures ──────────────────────────────────────────────────────

function makeContract(overrides?: Partial<TrustContract>): TrustContract {
  return {
    schema_version: "1.0",
    metadata: {
      name: "Test Contract",
      version: "1.0.0",
      author: "Test",
      description: "A test contract",
      effective_date: "2025-01-01",
    },
    data_governance: {
      allowed_input_classes: ["public"],
      allowed_output_classes: ["public"],
      retention_period: "P30D",
      cross_border_transfer: false,
    },
    rules: [
      {
        id: "R-001",
        description: "No PII in output",
        action: "*",
        conditions: [{ field: "output.contains_pii", operator: "equals", value: false }],
        on_violation: "block",
      },
      {
        id: "R-002",
        description: "Confidence threshold",
        action: "recommend",
        conditions: [{ field: "output.confidence", operator: "greater_than", value: 0.8 }],
        on_violation: "warn",
      },
    ],
    ...overrides,
  };
}

function makeContractWithModify(): TrustContract {
  return makeContract({
    rules: [
      {
        id: "R-001",
        description: "Block PII",
        action: "*",
        conditions: [{ field: "output.contains_pii", operator: "equals", value: false }],
        on_violation: "block",
      },
      {
        id: "R-003",
        description: "Redact sensitive",
        action: "generate",
        conditions: [{ field: "output.has_sensitive", operator: "equals", value: false }],
        on_violation: "modify",
        obligations: [
          {
            obligation_id: "OBL-1",
            type: "redact",
            params: { fields: ["ssn"] },
          },
        ],
      },
    ],
  });
}

function makeContractWithComplexConditions(): TrustContract {
  return makeContract({
    rules: [
      {
        id: "R-COMPLEX",
        description: "Complex nested conditions",
        action: ["generate", "summarize"],
        conditions: [
          {
            all: [
              { field: "input.safe", operator: "equals", value: true },
              {
                any: [
                  { field: "caller.role", operator: "in", value: ["admin", "reviewer"] },
                  { field: "metadata.override", operator: "exists", value: true },
                ],
              },
            ],
          },
          {
            not: { field: "input.blocked", operator: "equals", value: true },
          },
        ],
        on_violation: "block",
      },
    ],
  });
}

// ─── Tests ─────────────────────────────────────────────────────────

describe("TLAPlusGenerator", () => {
  const gen = new TLAPlusGenerator();

  describe("generate() - simple contract", () => {
    it("returns a valid TLAPlusSpec with correct moduleName", () => {
      const spec = gen.generate(makeContract());
      expect(spec.moduleName).toBe("Test_Contract");
      expect(spec.specContent).toBeTruthy();
      expect(spec.configContent).toBeTruthy();
      expect(spec.invariants).toContain("TypeInvariant");
      expect(spec.properties).toContain("EventuallyDecided");
    });

    it("generated spec contains MODULE header and closing ====", () => {
      const spec = gen.generate(makeContract());
      expect(spec.specContent).toContain("---- MODULE Test_Contract ----");
      expect(spec.specContent).toContain("====");
    });

    it("generated spec contains all field variables from conditions", () => {
      const spec = gen.generate(makeContract());
      expect(spec.specContent).toContain("f_output_contains_pii");
      expect(spec.specContent).toContain("f_output_confidence");
    });
  });

  describe("generate() - complex conditions", () => {
    it("nested all/any/not conditions produce valid TLA+ expressions", () => {
      const spec = gen.generate(makeContractWithComplexConditions());
      // all -> /\
      expect(spec.specContent).toContain("/\\");
      // any -> \/
      expect(spec.specContent).toContain("\\/");
      // not -> ~
      expect(spec.specContent).toContain("~(");
    });

    it("multiple rules produce separate rule predicates", () => {
      const contract = makeContract();
      const spec = gen.generate(contract);
      expect(spec.specContent).toContain("rule_R_001_passed");
      expect(spec.specContent).toContain("rule_R_002_passed");
    });
  });

  describe("generateConfig()", () => {
    it("config contains SPECIFICATION, CONSTANTS, INVARIANT lines", () => {
      const contract = makeContract();
      const config = gen.generateConfig(contract);
      expect(config).toContain("SPECIFICATION Spec");
      expect(config).toContain("CONSTANTS");
      expect(config).toContain('Permit = "permit"');
      expect(config).toContain('Deny = "deny"');
      expect(config).toContain('Modify = "modify"');
      expect(config).toContain("INVARIANT TypeInvariant");
    });

    it("config references correct invariants for block rules", () => {
      const contract = makeContract();
      const config = gen.generateConfig(contract);
      expect(config).toContain("INVARIANT NoPermitWhenBlockViolated");
    });
  });

  describe("invariant generation", () => {
    it("TypeInvariant is always generated", () => {
      const contract = makeContract({ rules: [] });
      const spec = gen.generate(contract);
      expect(spec.invariants).toContain("TypeInvariant");
    });

    it("NoPermitWhenBlockViolated generated when block rules exist", () => {
      const spec = gen.generate(makeContract());
      expect(spec.invariants).toContain("NoPermitWhenBlockViolated");
    });

    it("ModifyHasObligations generated when modify rules with obligations exist", () => {
      const spec = gen.generate(makeContractWithModify());
      expect(spec.invariants).toContain("ModifyHasObligations");
    });

    it("no NoPermitWhenBlockViolated when no block rules", () => {
      const contract = makeContract({
        rules: [
          {
            id: "R-W",
            description: "Warn only",
            action: "*",
            conditions: [{ field: "output.ok", operator: "equals", value: true }],
            on_violation: "warn",
          },
        ],
      });
      const spec = gen.generate(contract);
      expect(spec.invariants).not.toContain("NoPermitWhenBlockViolated");
    });
  });

  describe("operator mapping", () => {
    it("equals maps to =", () => {
      expect(leafToTLA("x", "equals", "foo")).toBe('x = "foo"');
    });

    it("not_equals maps to /=", () => {
      expect(leafToTLA("x", "not_equals", 42)).toBe("x /= 42");
    });

    it("greater_than maps to >", () => {
      expect(leafToTLA("x", "greater_than", 10)).toBe("x > 10");
    });

    it("less_than maps to <", () => {
      expect(leafToTLA("x", "less_than", 5)).toBe("x < 5");
    });

    it("contains maps to \\in", () => {
      expect(leafToTLA("x", "contains", "val")).toBe('"val" \\in x');
    });

    it("in maps to \\in {set}", () => {
      expect(leafToTLA("x", "in", ["a", "b"])).toBe('x \\in {"a", "b"}');
    });

    it("exists maps to NULL check", () => {
      expect(leafToTLA("x", "exists", true)).toBe('x /= "NULL"');
    });

    it("not_exists maps to NULL check", () => {
      expect(leafToTLA("x", "not_exists", true)).toBe('x = "NULL"');
    });

    it("matches maps to comment with regex", () => {
      expect(leafToTLA("x", "matches", "^foo.*")).toContain("regex: ^foo.*");
    });
  });

  describe("model checker", () => {
    it("returns unavailable when tlcPath not set", async () => {
      const gen = new TLAPlusGenerator();
      const spec = gen.generate(makeContract());
      const result = await gen.runModelChecker(spec);
      expect(result.status).toBe("unavailable");
      expect(result.invariantsChecked).toContain("TypeInvariant");
      expect(result.rawOutput).toContain("TLC path not configured");
    });

    it("returns unavailable when TLC jar path is invalid", async () => {
      const gen = new TLAPlusGenerator({
        tlcPath: "/nonexistent/tla2tools.jar",
      });
      const spec = gen.generate(makeContract());
      const result = await gen.runModelChecker(spec);
      // Will be "error" because java exec fails, not "unavailable"
      expect(["error", "unavailable"]).toContain(result.status);
      expect(result.invariantsChecked).toContain("TypeInvariant");
    });
  });

  describe("module name sanitization", () => {
    it("spaces and special characters are replaced with underscores", () => {
      expect(sanitizeModuleName("My Contract!")).toBe("My_Contract_");
      expect(sanitizeModuleName("hello-world.v2")).toBe("hello_world_v2");
      expect(sanitizeModuleName("simple")).toBe("simple");
      expect(sanitizeModuleName("has spaces & symbols")).toBe("has_spaces___symbols");
    });
  });

  describe("round-trip", () => {
    it("all rule IDs from the contract appear in the generated spec", () => {
      const contract = makeContract();
      const spec = gen.generate(contract);
      for (const rule of contract.rules) {
        expect(spec.specContent).toContain(sanitizeId(rule.id));
      }
    });

    it("generated spec is syntactically structured (has Init, Next, Spec)", () => {
      const spec = gen.generate(makeContract());
      expect(spec.specContent).toContain("Init ==");
      expect(spec.specContent).toContain("Next ==");
      expect(spec.specContent).toContain("Spec ==");
    });
  });

  describe("helper functions", () => {
    it("fieldToVar converts dot-separated fields", () => {
      expect(fieldToVar("output.contains_pii")).toBe("f_output_contains_pii");
      expect(fieldToVar("a.b.c")).toBe("f_a_b_c");
    });

    it("extractAllFields collects fields from nested conditions", () => {
      const rules: PolicyRule[] = [
        {
          id: "R1",
          description: "test",
          action: "*",
          conditions: [
            {
              all: [
                { field: "a.b", operator: "equals", value: true },
                { field: "c.d", operator: "equals", value: false },
              ],
            },
          ],
          on_violation: "block",
        },
      ];
      const fields = extractAllFields(rules);
      expect(fields).toContain("a.b");
      expect(fields).toContain("c.d");
    });

    it("tlaValue handles booleans, numbers, and strings", () => {
      expect(tlaValue(true)).toBe("TRUE");
      expect(tlaValue(false)).toBe("FALSE");
      expect(tlaValue(42)).toBe("42");
      expect(tlaValue("hello")).toBe('"hello"');
    });

    it("tlaSetValue handles arrays", () => {
      expect(tlaSetValue(["a", "b"])).toBe('{"a", "b"}');
      expect(tlaSetValue("single")).toBe('{"single"}');
    });
  });
});
