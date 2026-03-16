import { describe, it, expect } from "vitest";
import { GodClause, PolicyContext } from "../src";

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "generate",
    input: { prompt: "test" },
    output: { contains_pii: false },
    caller: { user_id: "u1", session_id: "s1", roles: ["user"] },
    ...overrides,
  };
}

const modifyContract = `
schema_version: "1.0"
metadata:
  name: Obligation Test
  version: "1.0.0"
  author: Test
  description: Test modify severity with obligations
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: MOD-001
    description: PII detected, require redaction
    action: generate
    conditions:
      - field: output.contains_pii
        operator: equals
        value: false
    on_violation: modify
    obligations:
      - obligation_id: OBL-001
        type: redact_pii
      - obligation_id: OBL-002
        type: log_enhanced
        params:
          level: detailed
  - id: BLK-001
    description: Block if toxic
    action: generate
    conditions:
      - field: output.toxic
        operator: equals
        value: false
    on_violation: block
`;

describe("Three-Valued Decisions with Obligations", () => {
  it("returns permit outcome when all conditions pass", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(modifyContract);
    const decision = await gov.evaluate(makeCtx({
      output: { contains_pii: false, toxic: false },
    }));
    expect(decision.outcome).toBe("permit");
    expect(decision.allowed).toBe(true);
    expect(decision.obligations).toHaveLength(0);
    expect(decision.modifications).toHaveLength(0);
  });

  it("returns modify outcome with obligations when modify rule fails", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(modifyContract);
    const decision = await gov.evaluate(makeCtx({
      output: { contains_pii: true, toxic: false },
    }));
    expect(decision.outcome).toBe("modify");
    expect(decision.allowed).toBe(true);
    expect(decision.obligations).toHaveLength(2);
    expect(decision.obligations[0].obligation_id).toBe("OBL-001");
    expect(decision.obligations[0].type).toBe("redact_pii");
    expect(decision.obligations[0].source_rule_id).toBe("MOD-001");
    expect(decision.obligations[1].params).toEqual({ level: "detailed" });
  });

  it("block overrides modify — returns deny", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(modifyContract);
    const decision = await gov.evaluate(makeCtx({
      output: { contains_pii: true, toxic: true },
    }));
    expect(decision.outcome).toBe("deny");
    expect(decision.allowed).toBe(false);
    expect(decision.blocks).toHaveLength(1);
    // Obligations still collected even though blocked
    expect(decision.obligations.length).toBeGreaterThan(0);
  });

  it("records obligations in audit entry", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(modifyContract);
    await gov.evaluate(makeCtx({
      output: { contains_pii: true, toxic: false },
    }));
    const entries = gov.getAuditEntries();
    expect(entries[0].outcome).toBe("modify");
    expect(entries[0].obligations).toContain("OBL-001");
    expect(entries[0].obligations).toContain("OBL-002");
  });

  it("schema validates modify severity and obligations", () => {
    const gov = new GodClause();
    // Should not throw
    const contract = gov.loadContractYAML(modifyContract);
    expect(contract.rules[0].on_violation).toBe("modify");
    expect(contract.rules[0].obligations).toHaveLength(2);
  });

  it("modifications array is populated on modify outcome", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(modifyContract);
    const decision = await gov.evaluate(makeCtx({
      output: { contains_pii: true, toxic: false },
    }));
    expect(decision.modifications).toHaveLength(1);
    expect(decision.modifications[0].rule_id).toBe("MOD-001");
  });
});
