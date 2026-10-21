import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { GodClause, PolicyContext } from "../src";

const healthcareYAML = readFileSync(join(__dirname, "../examples/healthcare-ai.contract.yaml"), "utf-8");

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "recommend",
    input: { prompt: "test" },
    output: {
      contains_phi: false,
      confidence: 0.92,
      disclaimer_present: true,
    },
    caller: {
      user_id: "dr-test",
      session_id: "sess-test",
      roles: ["clinician"],
    },
    metadata: { human_in_loop: true },
    ...overrides,
  };
}

describe("Audit Log", () => {
  it("records audit entries for every decision", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx({ action: "generate" }));

    const entries = gov.getAuditEntries();
    expect(entries.length).toBe(2);
  });

  it("maintains a valid hash chain", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx({ action: "classify" }));
    await gov.evaluate(
      makeCtx({
        action: "generate",
        output: { contains_phi: true, disclaimer_present: false },
      }),
    );

    const result = gov.verifyAuditChain();
    expect(result.valid).toBe(true);
  });

  it("detects tampered entries", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const entries = gov.getAuditEntries() as any[];
    entries[0].allowed = !entries[0].allowed;

    const result = gov.verifyAuditChain();
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it("supports querying by user_id", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx({ caller: { user_id: "alice", session_id: "s1", roles: ["clinician"] } }));
    await gov.evaluate(makeCtx({ caller: { user_id: "bob", session_id: "s2", roles: ["clinician"] } }));
    await gov.evaluate(makeCtx({ caller: { user_id: "alice", session_id: "s3", roles: ["clinician"] } }));

    const aliceEntries = gov.queryAudit({ user_id: "alice" });
    expect(aliceEntries.length).toBe(2);
  });

  it("supports querying by action type", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx({ action: "recommend" }));
    await gov.evaluate(makeCtx({ action: "classify" }));
    await gov.evaluate(makeCtx({ action: "recommend" }));

    const recommends = gov.queryAudit({ action: "recommend" });
    expect(recommends.length).toBe(2);
  });

  it("supports querying blocked-only decisions", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(
      makeCtx({
        action: "generate",
        output: { contains_phi: true, disclaimer_present: false },
      }),
    );

    const blocked = gov.queryAudit({ allowed: false });
    expect(blocked.length).toBe(1);
  });

  it("each entry has a unique hash", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const entries = gov.getAuditEntries();
    expect(entries[0].hash).not.toBe(entries[1].hash);
  });

  it("links entries via prev_hash", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const entries = gov.getAuditEntries();
    expect(entries[0].prev_hash).toBe("GENESIS");
    expect(entries[1].prev_hash).toBe(entries[0].hash);
  });

  it("includes logs in audit entries", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(`
schema_version: "1.0"
metadata:
  name: Log Audit Test
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
  - id: LA-001
    description: Log test
    action: "*"
    conditions:
      - field: input.x
        operator: equals
        value: 1
    on_violation: log
`);

    await gov.evaluate(makeCtx({ input: { x: 999 } }));
    const entries = gov.getAuditEntries();
    expect(entries[0].logs).toContain("LA-001");
  });

  it("detects tampering of warnings array (full-field hash)", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(
      makeCtx({
        output: { contains_phi: false, confidence: 0.5, disclaimer_present: true },
      }),
    );

    const entries = gov.getAuditEntries() as any[];
    entries[0].warnings = ["FAKE-001"];

    const result = gov.verifyAuditChain();
    expect(result.valid).toBe(false);
  });

  it("detects tampering of nested fields (caller, rule_results)", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const entries = gov.getAuditEntries() as any[];
    entries[0].caller.user_id = "someone-else";
    expect(gov.verifyAuditChain()).toEqual({ valid: false, brokenAt: 0 });

    entries[0].caller.user_id = "dr-test";
    expect(gov.verifyAuditChain().valid).toBe(true);

    entries[1].rule_results[0].passed = !entries[1].rule_results[0].passed;
    expect(gov.verifyAuditChain()).toEqual({ valid: false, brokenAt: 1 });
  });

  it("detects deletion of the first entry", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const entries = gov.getAuditEntries() as any[];
    entries.shift();
    expect(gov.verifyAuditChain()).toEqual({ valid: false, brokenAt: 0 });
  });

  it("detects truncation of the tail", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const entries = gov.getAuditEntries() as any[];
    entries.pop();
    expect(gov.verifyAuditChain()).toEqual({ valid: false, brokenAt: 2 });

    entries.length = 0;
    expect(gov.verifyAuditChain()).toEqual({ valid: false, brokenAt: 0 });
  });

  it("exposes the chain head for external anchoring", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    expect(gov.auditLog.headHash).toBe("GENESIS");
    await gov.evaluate(makeCtx());
    expect(gov.auditLog.headHash).toBe(gov.getAuditEntries()[0].hash);
  });

  it("verifyAuditEntries accepts a mid-chain slice; verifyChain does not", async () => {
    const { verifyAuditEntries } = await import("../src/audit/audit-log");
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const slice = [...gov.getAuditEntries()].slice(1);
    expect(verifyAuditEntries(slice).valid).toBe(true);
    expect(gov.auditLog.verifyChain(slice)).toEqual({ valid: false, brokenAt: 0 });
  });

  it("keeps verify and query working when custom sinks are configured", async () => {
    const { MemoryAuditSink } = await import("../src/audit/audit-log");
    const custom = new MemoryAuditSink();
    const gov = new GodClause({ auditSinks: [custom] });
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());

    expect(custom.entries.length).toBe(1);
    expect(gov.getAuditEntries().length).toBe(1);
    expect(gov.queryAudit({ user_id: "dr-test" }).length).toBe(1);
    expect(gov.verifyAuditChain().valid).toBe(true);
  });

  it("detects content injected under a __proto__ key", async () => {
    const { verifyAuditEntries } = await import("../src/audit/audit-log");
    const gov = new GodClause({ auditSecretKey: "k" });
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());

    const stored = JSON.stringify(gov.getAuditEntries()[0]);
    const injected = JSON.parse(stored.replace(/^\{/, '{"__proto__":{"allowed":true},'));
    expect(Object.keys(injected)).toContain("__proto__");
    expect(verifyAuditEntries([injected], "k")).toEqual({ valid: false, brokenAt: 0 });
  });

  it("snapshots the caller instead of aliasing it", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    const ctx = makeCtx();
    await gov.evaluate(ctx);
    ctx.caller.user_id = "mutated-later";
    ctx.caller.roles.push("admin");

    expect(gov.getAuditEntries()[0].caller.user_id).toBe("dr-test");
    expect(gov.verifyAuditChain().valid).toBe(true);
  });

  it("gives each sink its own copy of the entry", async () => {
    const mutating = {
      append(e: any) {
        e.allowed = !e.allowed;
        delete e.caller.roles;
      },
    };
    const gov = new GodClause({ auditSinks: [mutating] });
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());

    expect(gov.getAuditEntries()[0].caller.roles).toEqual(["clinician"]);
    expect(gov.verifyAuditChain().valid).toBe(true);
  });

  it("delivers entries to sinks in chain order when decisions overlap", async () => {
    const { verifyAuditEntries } = await import("../src/audit/audit-log");
    const seen: any[] = [];
    let first = true;
    const slow = {
      async append() {
        if (first) {
          first = false;
          await new Promise((r) => setTimeout(r, 20));
        }
      },
    };
    const recorder = { append: (e: any) => void seen.push(e) };
    const gov = new GodClause({ auditSinks: [slow, recorder] });
    gov.loadContractYAML(healthcareYAML);

    await Promise.all([gov.evaluate(makeCtx()), gov.evaluate(makeCtx()), gov.evaluate(makeCtx())]);

    expect(seen.map((e) => e.entry_id)).toEqual(gov.getAuditEntries().map((e) => e.entry_id));
    expect(verifyAuditEntries(seen, undefined, { prevHash: "GENESIS" }).valid).toBe(true);
  });

  it("keeps recording after a sink throws", async () => {
    let fail = true;
    const flaky = {
      append() {
        if (fail) {
          fail = false;
          throw new Error("sink down");
        }
      },
    };
    const gov = new GodClause({ auditSinks: [flaky] });
    gov.loadContractYAML(healthcareYAML);

    await expect(gov.evaluate(makeCtx())).rejects.toThrow("sink down");
    await expect(gov.evaluate(makeCtx())).resolves.toBeDefined();
    expect(gov.getAuditEntries()).toHaveLength(2);
  });

  it("resumes a chain from a persisted head and anchors both ends offline", async () => {
    const { verifyAuditEntries } = await import("../src/audit/audit-log");
    const first = new GodClause();
    first.loadContractYAML(healthcareYAML);
    await first.evaluate(makeCtx());
    await first.evaluate(makeCtx());

    const second = new GodClause({ auditHeadHash: first.auditLog.headHash });
    second.loadContractYAML(healthcareYAML);
    await second.evaluate(makeCtx());

    const file = [...first.getAuditEntries(), ...second.getAuditEntries()];
    const head = second.auditLog.headHash;
    expect(verifyAuditEntries(file, undefined, { prevHash: "GENESIS", headHash: head }).valid).toBe(true);
    expect(second.verifyAuditChain().valid).toBe(true);
    expect(verifyAuditEntries([...second.getAuditEntries()], undefined, { prevHash: "GENESIS" })).toEqual({
      valid: false,
      brokenAt: 0,
    });
    expect(verifyAuditEntries(file.slice(0, 2), undefined, { headHash: head })).toEqual({ valid: false, brokenAt: 2 });
  });

  it("sets hash_version to 3 on entries", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    const entries = gov.getAuditEntries();
    expect(entries[0].hash_version).toBe(3);
  });
});

describe("HMAC Signing", () => {
  it("signs entries when secret key is configured", async () => {
    const gov = new GodClause({ auditSecretKey: "test-secret-key-123" });
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    const entries = gov.getAuditEntries();
    expect(entries[0].hmac_signature).toBeDefined();
    expect(entries[0].hmac_signature!.length).toBe(64);
  });

  it("does not sign entries without secret key", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    const entries = gov.getAuditEntries();
    expect(entries[0].hmac_signature).toBeUndefined();
  });

  it("verifies HMAC on valid chain", async () => {
    const key = "my-secret";
    const gov = new GodClause({ auditSecretKey: key });
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const result = gov.verifyAuditChain(key);
    expect(result.valid).toBe(true);
  });

  it("detects HMAC tampering", async () => {
    const key = "my-secret";
    const gov = new GodClause({ auditSecretKey: key });
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const entries = gov.getAuditEntries() as any[];
    entries[0].hmac_signature = "0".repeat(64);

    const result = gov.verifyAuditChain(key);
    expect(result.valid).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it("prevents hash recomputation attack", async () => {
    const key = "my-secret";
    const gov = new GodClause({ auditSecretKey: key });
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());

    const entries = gov.getAuditEntries() as any[];
    entries[0].allowed = !entries[0].allowed;

    const result = gov.verifyAuditChain(key);
    expect(result.valid).toBe(false);
  });

  it("fails verification when a signature is stripped", async () => {
    const key = "my-secret";
    const gov = new GodClause({ auditSecretKey: key });
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const entries = gov.getAuditEntries() as any[];
    delete entries[1].hmac_signature;

    expect(gov.verifyAuditChain(key)).toEqual({ valid: false, brokenAt: 1 });
  });

  it("rejects an empty secret key", () => {
    expect(() => new GodClause({ auditSecretKey: "" })).toThrow("secretKey must not be empty");
  });

  it("does not skip HMAC checks for an empty verification key", async () => {
    const gov = new GodClause({ auditSecretKey: "k" });
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());

    expect(gov.verifyAuditChain("").valid).toBe(false);
  });
});

describe("Merkle Seal", () => {
  it("creates a seal over audit entries", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const seal = gov.sealAuditChain();
    expect(seal.entry_count).toBe(2);
    expect(seal.merkle_root).toBeDefined();
    expect(seal.merkle_root.length).toBe(64);
  });

  it("verifies a valid seal", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const seal = gov.sealAuditChain();
    expect(gov.verifyAuditSeal(seal)).toBe(true);
  });

  it("detects tampering after seal", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());

    const seal = gov.sealAuditChain();

    const entries = gov.getAuditEntries() as any[];
    entries[0].hash = "tampered";

    expect(gov.verifyAuditSeal(seal)).toBe(false);
  });

  it("creates separate seals for different ranges", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);

    await gov.evaluate(makeCtx());
    await gov.evaluate(makeCtx());
    const seal1 = gov.sealAuditChain();

    await gov.evaluate(makeCtx());
    const seal2 = gov.sealAuditChain();

    expect(seal1.entry_count).toBe(2);
    expect(seal2.entry_count).toBe(1);
    expect(seal1.merkle_root).not.toBe(seal2.merkle_root);

    expect(gov.verifyAuditSeal(seal1)).toBe(true);
    expect(gov.verifyAuditSeal(seal2)).toBe(true);
  });

  it("throws when no entries to seal", () => {
    const gov = new GodClause();
    gov.loadContractYAML(healthcareYAML);
    expect(() => gov.sealAuditChain()).toThrow("No new audit entries to seal");
  });
});

describe("Audit Log Sampling", () => {
  const simpleContract = `
schema_version: "1.0"
metadata:
  name: Sampling Test
  version: "1.0.0"
  author: Test
  description: Test sampling
  effective_date: "2025-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: S-001
    description: Block if flagged
    action: generate
    conditions:
      - field: output.flagged
        operator: equals
        value: false
    on_violation: block
    tags: [safety]
`;

  it("logs all permits when sample rate is 1.0 (default)", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(simpleContract);

    for (let i = 0; i < 20; i++) {
      await gov.evaluate({
        action: "generate",
        input: { prompt: "test" },
        output: { flagged: false },
        caller: { user_id: "u1", session_id: "s1", roles: [] },
      });
    }

    expect(gov.getAuditEntries().length).toBe(20);
  });

  it("logs zero permits when sample rate is 0.0", async () => {
    const { AuditLog, MemoryAuditSink } = await import("../src/audit/audit-log");

    const sink = new MemoryAuditSink();
    const log = new AuditLog({ sinks: [sink], permitSampleRate: 0.0 });

    // Create a mock permit decision
    for (let i = 0; i < 50; i++) {
      const result = await log.record(
        {
          decision_id: `d-${i}`,
          allowed: true,
          outcome: "permit",
          evaluations: [],
          warnings: [],
          blocks: [],
          logs: [],
          modifications: [],
          obligations: [],
          timestamp: new Date().toISOString(),
          context: {
            action: "generate",
            input: {},
            caller: { user_id: "u1", session_id: "s1", roles: [] },
          },
        },
        {
          schema_version: "1.0",
          metadata: { name: "T", version: "1.0.0", author: "T", description: "T", effective_date: "2025-01-01" },
          data_governance: {
            allowed_input_classes: ["public"],
            allowed_output_classes: ["public"],
            retention_period: "P30D",
            cross_border_transfer: false,
          },
          rules: [],
        },
      );
      // result should be null (sampled out)
      expect(result).toBeNull();
    }

    expect(sink.entries.length).toBe(0);
  });

  it("always logs deny decisions regardless of sample rate", async () => {
    const { AuditLog, MemoryAuditSink } = await import("../src/audit/audit-log");

    const sink = new MemoryAuditSink();
    const log = new AuditLog({ sinks: [sink], permitSampleRate: 0.0 });

    const contract = {
      schema_version: "1.0",
      metadata: { name: "T", version: "1.0.0", author: "T", description: "T", effective_date: "2025-01-01" },
      data_governance: {
        allowed_input_classes: ["public" as const],
        allowed_output_classes: ["public" as const],
        retention_period: "P30D",
        cross_border_transfer: false,
      },
      rules: [],
    };

    // Deny decisions should always be logged
    for (let i = 0; i < 10; i++) {
      const result = await log.record(
        {
          decision_id: `d-${i}`,
          allowed: false,
          outcome: "deny",
          evaluations: [],
          warnings: [],
          blocks: [
            {
              rule_id: "R-1",
              rule_description: "test",
              passed: false,
              severity: "block",
              violated_conditions: [],
              timestamp: new Date().toISOString(),
            },
          ],
          logs: [],
          modifications: [],
          obligations: [],
          timestamp: new Date().toISOString(),
          context: {
            action: "generate",
            input: {},
            caller: { user_id: "u1", session_id: "s1", roles: [] },
          },
        },
        contract,
      );
      expect(result).not.toBeNull();
    }

    expect(sink.entries.length).toBe(10);
  });

  it("always logs modify decisions regardless of sample rate", async () => {
    const { AuditLog, MemoryAuditSink } = await import("../src/audit/audit-log");

    const sink = new MemoryAuditSink();
    const log = new AuditLog({ sinks: [sink], permitSampleRate: 0.0 });

    const contract = {
      schema_version: "1.0",
      metadata: { name: "T", version: "1.0.0", author: "T", description: "T", effective_date: "2025-01-01" },
      data_governance: {
        allowed_input_classes: ["public" as const],
        allowed_output_classes: ["public" as const],
        retention_period: "P30D",
        cross_border_transfer: false,
      },
      rules: [],
    };

    for (let i = 0; i < 10; i++) {
      const result = await log.record(
        {
          decision_id: `d-${i}`,
          allowed: true,
          outcome: "modify",
          evaluations: [],
          warnings: [],
          blocks: [],
          logs: [],
          modifications: [],
          obligations: [{ obligation_id: "o1", type: "redact_pii", source_rule_id: "r1" }],
          timestamp: new Date().toISOString(),
          context: {
            action: "generate",
            input: {},
            caller: { user_id: "u1", session_id: "s1", roles: [] },
          },
        },
        contract,
      );
      expect(result).not.toBeNull();
    }

    expect(sink.entries.length).toBe(10);
  });
});
