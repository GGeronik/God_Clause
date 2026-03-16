import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { parseContract, serializeContract, summarizeContract, ContractParseError } from "../src";

const healthcareYAML = readFileSync(join(__dirname, "../examples/healthcare-ai.contract.yaml"), "utf-8");

describe("Trust Contract Parser", () => {
  it("parses a valid YAML contract", () => {
    const contract = parseContract(healthcareYAML);
    expect(contract.metadata.name).toBe("Healthcare AI Governance");
    expect(contract.rules).toHaveLength(5);
    expect(contract.data_governance.cross_border_transfer).toBe(false);
  });

  it("parses a valid JSON contract", () => {
    const contract = parseContract(healthcareYAML);
    const json = JSON.stringify(contract);
    const reparsed = parseContract(json);
    expect(reparsed.metadata.name).toBe(contract.metadata.name);
    expect(reparsed.rules).toHaveLength(contract.rules.length);
  });

  it("throws ContractParseError on invalid input", () => {
    expect(() => parseContract("not: valid: yaml: [")).toThrow();
  });

  it("throws ContractParseError when required fields are missing", () => {
    const invalid = JSON.stringify({ schema_version: "1.0" });
    expect(() => parseContract(invalid)).toThrow(ContractParseError);
  });

  it("round-trips through serialize and parse", () => {
    const original = parseContract(healthcareYAML);
    const yaml = serializeContract(original);
    const reparsed = parseContract(yaml);
    expect(reparsed.metadata.name).toBe(original.metadata.name);
    expect(reparsed.rules).toHaveLength(original.rules.length);
  });

  it("generates a human-readable summary", () => {
    const contract = parseContract(healthcareYAML);
    const summary = summarizeContract(contract);
    expect(summary).toContain("Healthcare AI Governance");
    expect(summary).toContain("HC-001");
    expect(summary).toContain("Prohibited"); // cross_border_transfer = false
  });

  it("accepts custom action verbs", () => {
    const yaml = `
schema_version: "1.0"
metadata:
  name: Custom Actions
  version: "1.0.0"
  author: Test
  description: Test custom actions
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: CUSTOM-001
    description: Custom audit action
    action: audit
    conditions:
      - field: input.target
        operator: exists
        value: true
    on_violation: warn
`;
    const contract = parseContract(yaml);
    expect(contract.rules[0].action).toBe("audit");
  });

  it("parses composite conditions (any/all/not)", () => {
    const yaml = `
schema_version: "1.0"
metadata:
  name: Composite Test
  version: "1.0.0"
  author: Test
  description: Test composite conditions
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: COMP-001
    description: Complex composite rule
    action: generate
    conditions:
      - any:
          - field: caller.roles
            operator: contains
            value: admin
          - all:
              - field: output.confidence
                operator: greater_than
                value: 0.9
              - not:
                  field: output.flagged
                  operator: equals
                  value: true
    on_violation: block
`;
    const contract = parseContract(yaml);
    const cond = contract.rules[0].conditions[0];
    expect("any" in cond).toBe(true);
  });

  it("summarizes composite conditions with indentation", () => {
    const yaml = `
schema_version: "1.0"
metadata:
  name: Summary Test
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
  - id: S-001
    description: Test
    action: generate
    conditions:
      - any:
          - field: caller.roles
            operator: contains
            value: admin
          - field: caller.roles
            operator: contains
            value: super
    on_violation: block
`;
    const contract = parseContract(yaml);
    const summary = summarizeContract(contract);
    expect(summary).toContain("ANY of:");
  });
});
