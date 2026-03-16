import { describe, it, expect } from "vitest";
import { parseContract, resolveInheritance, ContractParseError } from "../src/contracts/parser";
import { ContractRegistry } from "../src/contracts/registry";

const baseContract = `
schema_version: "1.0"
metadata:
  name: Base Safety
  version: "1.0.0"
  author: Safety Team
  description: Base safety contract
  effective_date: "2025-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P90D
  cross_border_transfer: false
rules:
  - id: BASE-001
    description: Block toxic content
    action: generate
    conditions:
      - field: output.toxicity
        operator: less_than
        value: 0.5
    on_violation: block
    tags: [safety]
  - id: BASE-002
    description: Redact PII
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
    tags: [privacy]
`;

const childContract = `
schema_version: "1.0"
extends: "Base Safety"
metadata:
  name: Healthcare Safety
  version: "1.0.0"
  author: Healthcare Team
  description: Healthcare-specific safety
  effective_date: "2025-01-01"
data_governance:
  allowed_input_classes: [public, internal]
  allowed_output_classes: [public]
  retention_period: P365D
  cross_border_transfer: false
rules:
  - id: HC-001
    description: Require human review for clinical decisions
    action: decide
    conditions:
      - field: output.confidence
        operator: greater_than
        value: 0.95
    on_violation: modify
    obligations:
      - obligation_id: OBL-REVIEW
        type: require_review
        params: { escalate_to: clinician }
    tags: [clinical]
`;

const childWithOverride = `
schema_version: "1.0"
extends: "Base Safety"
metadata:
  name: Strict Safety
  version: "1.0.0"
  author: Compliance Team
  description: Stricter safety overrides
  effective_date: "2025-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P365D
  cross_border_transfer: false
override_rules:
  - id: BASE-001
    description: Block toxic content (stricter threshold)
    action: generate
    conditions:
      - field: output.toxicity
        operator: less_than
        value: 0.1
    on_violation: block
    tags: [safety, strict]
rules:
  - id: STRICT-001
    description: Block unverified outputs
    action: generate
    conditions:
      - field: output.verified
        operator: equals
        value: true
    on_violation: block
    tags: [compliance]
`;

describe("Contract Inheritance", () => {
  it("child inherits all parent rules", () => {
    const registry = new ContractRegistry();
    const parent = parseContract(baseContract);
    registry.register(parent, { activate: true });

    const child = parseContract(childContract);
    const resolved = resolveInheritance(child, registry);

    // Should have parent's 2 rules + child's 1 rule = 3
    expect(resolved.rules).toHaveLength(3);
    expect(resolved.rules.map((r) => r.id)).toEqual(["BASE-001", "BASE-002", "HC-001"]);
  });

  it("child can add new rules", () => {
    const registry = new ContractRegistry();
    registry.register(parseContract(baseContract), { activate: true });

    const child = parseContract(childContract);
    const resolved = resolveInheritance(child, registry);

    const hcRule = resolved.rules.find((r) => r.id === "HC-001");
    expect(hcRule).toBeDefined();
    expect(hcRule!.description).toBe("Require human review for clinical decisions");
    expect(hcRule!.tags).toContain("clinical");
  });

  it("child preserves its own metadata", () => {
    const registry = new ContractRegistry();
    registry.register(parseContract(baseContract), { activate: true });

    const child = parseContract(childContract);
    const resolved = resolveInheritance(child, registry);

    expect(resolved.metadata.name).toBe("Healthcare Safety");
    expect(resolved.metadata.author).toBe("Healthcare Team");
    expect(resolved.data_governance.retention_period).toBe("P365D");
  });

  it("override_rules replace parent rules with matching IDs", () => {
    const registry = new ContractRegistry();
    registry.register(parseContract(baseContract), { activate: true });

    const child = parseContract(childWithOverride);
    const resolved = resolveInheritance(child, registry);

    // BASE-001 should be overridden (stricter threshold)
    const base001 = resolved.rules.find((r) => r.id === "BASE-001");
    expect(base001).toBeDefined();
    expect(base001!.description).toBe("Block toxic content (stricter threshold)");
    expect(base001!.tags).toContain("strict");

    // Check the condition value was overridden
    const leafCond = base001!.conditions[0];
    expect("value" in leafCond && leafCond.value).toBe(0.1);

    // BASE-002 should be unchanged (not overridden)
    const base002 = resolved.rules.find((r) => r.id === "BASE-002");
    expect(base002).toBeDefined();
    expect(base002!.description).toBe("Redact PII");

    // Child's own rule should be present
    const strict001 = resolved.rules.find((r) => r.id === "STRICT-001");
    expect(strict001).toBeDefined();
  });

  it("resolved contract has extends cleared", () => {
    const registry = new ContractRegistry();
    registry.register(parseContract(baseContract), { activate: true });

    const child = parseContract(childContract);
    const resolved = resolveInheritance(child, registry);

    expect(resolved.extends).toBeUndefined();
    expect(resolved.override_rules).toBeUndefined();
  });

  it("throws on missing parent", () => {
    const registry = new ContractRegistry();
    const child = parseContract(childContract);

    expect(() => resolveInheritance(child, registry)).toThrow(
      'Parent contract "Base Safety" not found',
    );
  });

  it("detects circular inheritance", () => {
    const registry = new ContractRegistry();

    // Create A extends B, B extends A scenario
    const contractA = parseContract(`
      schema_version: "1.0"
      extends: "Contract B"
      metadata:
        name: Contract A
        version: "1.0.0"
        author: Test
        description: A
        effective_date: "2025-01-01"
      data_governance:
        allowed_input_classes: [public]
        allowed_output_classes: [public]
        retention_period: P30D
        cross_border_transfer: false
      rules: []
    `);

    const contractB = parseContract(`
      schema_version: "1.0"
      extends: "Contract A"
      metadata:
        name: Contract B
        version: "1.0.0"
        author: Test
        description: B
        effective_date: "2025-01-01"
      data_governance:
        allowed_input_classes: [public]
        allowed_output_classes: [public]
        retention_period: P30D
        cross_border_transfer: false
      rules: []
    `);

    registry.register(contractA, { activate: true });
    registry.register(contractB, { activate: true });

    // Resolving A should detect the cycle
    expect(() => resolveInheritance(contractA, registry)).toThrow("Circular inheritance");
  });

  it("contract without extends returns unchanged", () => {
    const registry = new ContractRegistry();
    const contract = parseContract(baseContract);
    const result = resolveInheritance(contract, registry);

    expect(result).toBe(contract); // Same reference, no processing
  });

  it("child can override parent rule with same ID in rules array", () => {
    const registry = new ContractRegistry();
    registry.register(parseContract(baseContract), { activate: true });

    // Child redefines BASE-001 directly in rules (not override_rules)
    const child = parseContract(`
      schema_version: "1.0"
      extends: "Base Safety"
      metadata:
        name: Custom Safety
        version: "1.0.0"
        author: Custom Team
        description: Custom overrides
        effective_date: "2025-01-01"
      data_governance:
        allowed_input_classes: [public]
        allowed_output_classes: [public]
        retention_period: P30D
        cross_border_transfer: false
      rules:
        - id: BASE-001
          description: Custom toxicity rule
          action: generate
          conditions:
            - field: output.toxicity
              operator: less_than
              value: 0.2
          on_violation: block
          tags: [safety, custom]
    `);

    const resolved = resolveInheritance(child, registry);
    const rule = resolved.rules.find((r) => r.id === "BASE-001");
    expect(rule!.description).toBe("Custom toxicity rule");
    expect(rule!.tags).toContain("custom");
  });
});

describe("Audit Log Sampling", () => {
  // Import AuditLog separately for sampling tests
  it("is tested in audit.test.ts", () => {
    expect(true).toBe(true);
  });
});
