import { describe, it, expect } from "vitest";
import { GodClause, PolicyContext } from "../src";

const simpleContract = `
schema_version: "1.0"
metadata:
  name: Tenant Contract
  version: "1.0.0"
  author: Test
  description: Test tenancy
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: T-001
    description: Block without prompt
    action: generate
    conditions:
      - field: input.prompt
        operator: exists
        value: true
    on_violation: block
`;

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "generate",
    input: { prompt: "test" },
    caller: { user_id: "u1", session_id: "s1", roles: [] },
    ...overrides,
  };
}

describe("Multi-Tenancy", () => {
  it("creates isolated tenant scopes", () => {
    const gov = new GodClause();
    const tenantA = gov.createTenant("tenant-a", { tenantName: "Tenant A" });
    const tenantB = gov.createTenant("tenant-b");
    expect(tenantA.tenantId).toBe("tenant-a");
    expect(tenantA.tenantName).toBe("Tenant A");
    expect(tenantB.tenantId).toBe("tenant-b");
  });

  it("throws on duplicate tenant ID", () => {
    const gov = new GodClause();
    gov.createTenant("tenant-a");
    expect(() => gov.createTenant("tenant-a")).toThrow("already exists");
  });

  it("tenants have isolated contracts", async () => {
    const gov = new GodClause();
    const tenantA = gov.createTenant("tenant-a");
    const tenantB = gov.createTenant("tenant-b");

    tenantA.loadContractYAML(simpleContract);
    // tenantB has no contracts

    const dA = await tenantA.evaluate(makeCtx({ input: {} }));
    expect(dA.allowed).toBe(false);

    const dB = await tenantB.evaluate(makeCtx({ input: {} }));
    expect(dB.allowed).toBe(true); // no contracts to block
  });

  it("tenants have isolated audit logs", async () => {
    const gov = new GodClause();
    const tenantA = gov.createTenant("tenant-a");
    const tenantB = gov.createTenant("tenant-b");

    tenantA.loadContractYAML(simpleContract);
    tenantB.loadContractYAML(simpleContract);

    await tenantA.evaluate(makeCtx());
    await tenantA.evaluate(makeCtx());
    await tenantB.evaluate(makeCtx());

    expect(tenantA.getAuditEntries()).toHaveLength(2);
    expect(tenantB.getAuditEntries()).toHaveLength(1);
  });

  it("injects tenant_id into audit entries", async () => {
    const gov = new GodClause();
    const tenant = gov.createTenant("tenant-x");
    tenant.loadContractYAML(simpleContract);

    await tenant.evaluate(makeCtx());
    const entries = tenant.getAuditEntries();
    expect(entries[0].tenant_id).toBe("tenant-x");
    expect(entries[0].caller.tenant_id).toBe("tenant-x");
  });

  it("queryAllTenantsAudit aggregates across tenants", async () => {
    const gov = new GodClause();
    const tenantA = gov.createTenant("tenant-a");
    const tenantB = gov.createTenant("tenant-b");

    tenantA.loadContractYAML(simpleContract);
    tenantB.loadContractYAML(simpleContract);

    await tenantA.evaluate(makeCtx());
    await tenantB.evaluate(makeCtx());

    const all = gov.queryAllTenantsAudit({});
    expect(all).toHaveLength(2);
  });

  it("getTenant and removeTenant work", () => {
    const gov = new GodClause();
    gov.createTenant("tenant-a");
    expect(gov.getTenant("tenant-a")).toBeDefined();
    expect(gov.getTenant("nonexistent")).toBeUndefined();

    gov.removeTenant("tenant-a");
    expect(gov.getTenant("tenant-a")).toBeUndefined();
  });

  it("tenant audit chain integrity", async () => {
    const gov = new GodClause();
    const tenant = gov.createTenant("tenant-a");
    tenant.loadContractYAML(simpleContract);

    await tenant.evaluate(makeCtx());
    await tenant.evaluate(makeCtx());

    const result = tenant.verifyAuditChain();
    expect(result.valid).toBe(true);
  });
});
