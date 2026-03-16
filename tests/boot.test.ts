import { describe, it, expect } from "vitest";
import { GodClause } from "../src/governance";
import { SecureBoot, SecureBootOptions } from "../src/engine/boot";

const TEST_CONTRACT_YAML = `
schema_version: "1.0"
metadata:
  name: Test Contract
  version: "1.0.0"
  author: Test
  description: Test
  effective_date: "2025-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: T-001
    description: Test rule
    action: "*"
    conditions:
      - field: output.safe
        operator: equals
        value: true
    on_violation: block
`;

const SECOND_CONTRACT_YAML = `
schema_version: "1.0"
metadata:
  name: Second Contract
  version: "2.0.0"
  author: Test
  description: Second test contract
  effective_date: "2025-06-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: T-002
    description: Second test rule
    action: "*"
    conditions:
      - field: output.valid
        operator: equals
        value: true
    on_violation: warn
`;

describe("SecureBoot", () => {
  it("boots successfully with a valid contract", async () => {
    const { gov, preflight } = await SecureBoot.initialize({
      contracts: [TEST_CONTRACT_YAML],
    });

    expect(gov).toBeInstanceOf(GodClause);
    expect(preflight.ready).toBe(true);
  });

  it("returns a PreFlightResult with check details", async () => {
    const { preflight } = await SecureBoot.initialize({
      contracts: [TEST_CONTRACT_YAML],
    });

    expect(preflight).toHaveProperty("ready");
    expect(preflight).toHaveProperty("checks");
    expect(preflight).toHaveProperty("degradation_tier");
    expect(Array.isArray(preflight.checks)).toBe(true);
    expect(preflight.checks.length).toBeGreaterThanOrEqual(2);
  });

  it("PreFlight passes when contracts are loaded", async () => {
    const { preflight } = await SecureBoot.initialize({
      contracts: [TEST_CONTRACT_YAML],
    });

    const contractsCheck = preflight.checks.find(
      (c) => c.name === "contracts_loaded",
    );
    expect(contractsCheck).toBeDefined();
    expect(contractsCheck!.passed).toBe(true);
  });

  it("PreFlight fails when no contracts are loaded", async () => {
    const { preflight } = await SecureBoot.initialize({
      contracts: [],
    });

    expect(preflight.ready).toBe(false);
    const contractsCheck = preflight.checks.find(
      (c) => c.name === "contracts_loaded",
    );
    expect(contractsCheck).toBeDefined();
    expect(contractsCheck!.passed).toBe(false);
  });

  it("reports correct degradation tier when no contracts loaded", async () => {
    const { preflight } = await SecureBoot.initialize({
      contracts: [],
    });

    expect(preflight.degradation_tier).toBe(3);
  });

  it("loads multiple contracts successfully", async () => {
    const { gov, preflight } = await SecureBoot.initialize({
      contracts: [TEST_CONTRACT_YAML, SECOND_CONTRACT_YAML],
    });

    expect(preflight.ready).toBe(true);
    expect(gov.getContracts()).toHaveLength(2);
  });

  it("passes secretKey through to audit configuration", async () => {
    const { gov, preflight } = await SecureBoot.initialize({
      contracts: [TEST_CONTRACT_YAML],
      secretKey: "test-secret-key",
    });

    expect(preflight.ready).toBe(true);
    // The GodClause instance should be created successfully with the secret key
    expect(gov).toBeInstanceOf(GodClause);
  });

  it("verifyPreFlight on fresh GodClause (no contracts) reports not ready", () => {
    const gov = new GodClause();
    const result = SecureBoot.verifyPreFlight(gov);

    expect(result.ready).toBe(false);
    expect(result.degradation_tier).toBe(3);
  });

  it("verifyPreFlight with contracts reports ready", () => {
    const gov = new GodClause();
    gov.loadContractYAML(TEST_CONTRACT_YAML);

    const result = SecureBoot.verifyPreFlight(gov);

    expect(result.ready).toBe(true);
    expect(result.degradation_tier).toBe(0);
  });

  it("handles empty contracts array gracefully", async () => {
    const { gov, preflight } = await SecureBoot.initialize({
      contracts: [],
    });

    expect(gov).toBeInstanceOf(GodClause);
    expect(preflight.ready).toBe(false);
    expect(gov.getContracts()).toHaveLength(0);
  });

  it("PreFlight check names are descriptive", async () => {
    const { preflight } = await SecureBoot.initialize({
      contracts: [TEST_CONTRACT_YAML],
    });

    const checkNames = preflight.checks.map((c) => c.name);
    expect(checkNames).toContain("contracts_loaded");
    expect(checkNames).toContain("audit_writable");

    // All checks should have detail strings
    for (const check of preflight.checks) {
      expect(check.detail).toBeDefined();
      expect(typeof check.detail).toBe("string");
      expect(check.detail!.length).toBeGreaterThan(0);
    }
  });

  it("reports degradation tier 0 when all checks pass", async () => {
    const { preflight } = await SecureBoot.initialize({
      contracts: [TEST_CONTRACT_YAML],
    });

    expect(preflight.degradation_tier).toBe(0);
    expect(preflight.ready).toBe(true);
    expect(preflight.checks.every((c) => c.passed)).toBe(true);
  });
});
