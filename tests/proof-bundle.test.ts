import { describe, it, expect } from "vitest";
import { GodClause } from "../src/governance";
import { ProofBundleBuilder } from "../src/audit/proof-bundle";
import type { PolicyContext } from "../src/types";

const testContract = `
schema_version: "1.0"
metadata:
  name: Proof Bundle Test
  version: "1.0.0"
  author: Test
  description: Test contract for proof bundles
  effective_date: "2025-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: PB-001
    description: Block unsafe output
    action: generate
    conditions:
      - field: output.safe
        operator: equals
        value: true
    on_violation: block
    tags: [safety]
`;

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "generate",
    input: { prompt: "test" },
    output: { safe: true },
    caller: { user_id: "user-1", session_id: "sess-1", roles: [] },
    ...overrides,
  };
}

describe("Proof Bundle Builder", () => {
  it("builds a bundle with audit entries", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build();

    expect(bundle.bundle_id).toBeDefined();
    expect(bundle.created_at).toBeDefined();
    expect(bundle.audit_entries.length).toBe(2);
    expect(bundle.chain_verification.valid).toBe(true);
    expect(bundle.metadata.generator).toBe("god-clause");
  });

  it("includes contracts by default", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    await gov.evaluate(makeCtx());

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build();

    expect(bundle.contracts.length).toBe(1);
    expect(bundle.contracts[0].metadata.name).toBe("Proof Bundle Test");
  });

  it("excludes contracts when requested", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    await gov.evaluate(makeCtx());

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build({ includeContracts: false });

    expect(bundle.contracts.length).toBe(0);
  });

  it("exports to JSON", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    await gov.evaluate(makeCtx());

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build();
    const json = await builder.exportJSON(bundle);

    expect(typeof json).toBe("string");
    const parsed = JSON.parse(json);
    expect(parsed.bundle_id).toBe(bundle.bundle_id);
  });

  it("verifies a valid bundle", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build();
    const result = await builder.verify(bundle);

    expect(result.valid).toBe(true);
    expect(result.chain_valid).toBe(true);
    expect(result.seals_valid).toBe(true);
  });

  it("detects tampered entries in bundle", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build();

    // Tamper with an entry's hash
    bundle.audit_entries[0].hash = "tampered";

    const result = await builder.verify(bundle);
    expect(result.valid).toBe(false);
    expect(result.chain_valid).toBe(false);
  });

  it("verifies bundle with Merkle seals", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const seal = gov.sealAuditChain();

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build({ seals: [seal] });

    expect(bundle.merkle_seals.length).toBe(1);

    const result = await builder.verify(bundle);
    expect(result.valid).toBe(true);
    expect(result.seals_valid).toBe(true);
  });

  it("detects tampered seals in bundle", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const seal = gov.sealAuditChain();

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build({ seals: [seal] });

    // Tamper with the seal
    bundle.merkle_seals[0].merkle_root = "tampered";

    const result = await builder.verify(bundle);
    expect(result.valid).toBe(false);
    expect(result.seals_valid).toBe(false);
  });

  it("builds an empty bundle from fresh instance", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build();

    expect(bundle.audit_entries.length).toBe(0);
    expect(bundle.chain_verification.valid).toBe(true);
  });

  it("includes human overrides when provided", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    await gov.evaluate(makeCtx());

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build({
      humanOverrides: [
        {
          override_id: "ovr-1",
          decision_id: "dec-1",
          action: "approve",
          reason: "False positive",
          overrider_id: "admin-1",
          signature: "abc123",
          public_key: "pubkey123",
          timestamp: new Date().toISOString(),
        },
      ],
    });

    expect(bundle.human_overrides?.length).toBe(1);
    expect(bundle.human_overrides![0].reason).toBe("False positive");
  });

  it("each bundle gets a unique ID", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(testContract);

    const builder = new ProofBundleBuilder(gov);
    const b1 = await builder.build();
    const b2 = await builder.build();

    expect(b1.bundle_id).not.toBe(b2.bundle_id);
  });
});
