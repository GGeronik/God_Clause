import { describe, it, expect } from "vitest";
import { GodClause, ContractRegistry, parseContract, PolicyContext } from "../src";

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "generate",
    input: { prompt: "test" },
    caller: { user_id: "u1", session_id: "s1", roles: [] },
    ...overrides,
  };
}

function makeContract(version: string, ruleSeverity: "block" | "warn" = "block") {
  return `
schema_version: "1.0"
metadata:
  name: Versioned Contract
  version: "${version}"
  author: Test
  description: Test versioning
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: V-001
    description: Check prompt exists
    action: generate
    conditions:
      - field: input.prompt
        operator: exists
        value: true
    on_violation: ${ruleSeverity}
`;
}

describe("Contract Registry", () => {
  it("registers and retrieves active contracts", () => {
    const registry = new ContractRegistry();
    const contract = parseContract(makeContract("1.0.0"));
    registry.register(contract);
    expect(registry.getAllActive()).toHaveLength(1);
    expect(registry.getActive("Versioned Contract")?.metadata.version).toBe("1.0.0");
  });

  it("supports multiple versions of the same contract", () => {
    const registry = new ContractRegistry();
    registry.register(parseContract(makeContract("1.0.0")));
    registry.register(parseContract(makeContract("2.0.0")));
    expect(registry.getAllActive()).toHaveLength(2);
  });

  it("activates and deactivates versions", () => {
    const registry = new ContractRegistry();
    registry.register(parseContract(makeContract("1.0.0")));
    registry.register(parseContract(makeContract("2.0.0")));

    registry.deactivate("Versioned Contract", "1.0.0");
    expect(registry.getAllActive()).toHaveLength(1);
    expect(registry.getAllActive()[0].metadata.version).toBe("2.0.0");

    registry.activate("Versioned Contract", "1.0.0");
    expect(registry.getAllActive()).toHaveLength(2);
  });

  it("retrieves a specific version", () => {
    const registry = new ContractRegistry();
    registry.register(parseContract(makeContract("1.0.0")));
    registry.register(parseContract(makeContract("2.0.0")));

    const v1 = registry.getVersion("Versioned Contract", "1.0.0");
    expect(v1?.metadata.version).toBe("1.0.0");
  });

  it("lists all contracts", () => {
    const registry = new ContractRegistry();
    registry.register(parseContract(makeContract("1.0.0")));
    registry.register(parseContract(makeContract("2.0.0")));

    const list = registry.list();
    expect(list).toHaveLength(1);
    expect(list[0].versions).toEqual(["1.0.0", "2.0.0"]);
  });

  it("throws on activating unknown version", () => {
    const registry = new ContractRegistry();
    expect(() => registry.activate("Unknown", "1.0.0")).toThrow("not found");
  });
});

describe("GodClause Contract Versioning", () => {
  it("loadContractVersion without activation", async () => {
    const gov = new GodClause();
    gov.loadContractVersion(makeContract("1.0.0"), { activate: false });
    // Should not have any active contracts
    expect(gov.getContracts()).toHaveLength(0);
    // But should be in registry
    const versions = gov.getContractVersions("Versioned Contract");
    expect(versions).toHaveLength(1);
    expect(versions[0].activeVersion).toBeNull();
  });

  it("activateContract makes version active", async () => {
    const gov = new GodClause();
    gov.loadContractVersion(makeContract("1.0.0"), { activate: false });
    gov.activateContract("Versioned Contract", "1.0.0");
    expect(gov.getContracts()).toHaveLength(1);
  });

  it("deactivateContract removes version from evaluation", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(makeContract("1.0.0"));
    expect(gov.getContracts()).toHaveLength(1);

    gov.deactivateContract("Versioned Contract", "1.0.0");
    expect(gov.getContracts()).toHaveLength(0);

    // Should still allow since no active contracts
    const decision = await gov.evaluate(makeCtx({ input: {} }));
    expect(decision.allowed).toBe(true);
  });

  it("graceful rollover between versions", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(makeContract("1.0.0", "block"));
    gov.loadContractVersion(makeContract("2.0.0", "warn"), { activate: false });

    // v1 blocks missing prompt
    const d1 = await gov.evaluate(makeCtx({ input: {} }));
    expect(d1.allowed).toBe(false);

    // Activate v2, deactivate v1
    gov.activateContract("Versioned Contract", "2.0.0");
    gov.deactivateContract("Versioned Contract", "1.0.0");

    // v2 only warns
    const d2 = await gov.evaluate(makeCtx({ input: {} }));
    expect(d2.allowed).toBe(true);
    expect(d2.warnings).toHaveLength(1);
  });
});
