import { describe, it, expect, beforeEach } from "vitest";
import { GodClause } from "../src/governance";
import { generateComplianceReport } from "../src/compliance/reporter";
import { lintContract } from "../src/cli/linter";
import { parseContract } from "../src/contracts/parser";
import { exportAuditCSV, exportAuditJSON, exportAuditSummary } from "../src/audit/exporter";
import { DecisionCache } from "../src/engine/cache";
import { ContractChangeLog } from "../src/contracts/changelog";
import { MultiAuditSink } from "../src/audit/sinks/multi-sink";
import { MemoryAuditSink } from "../src/audit/audit-log";

const HEALTHCARE_CONTRACT = `
schema_version: "1.0"
metadata:
  name: Healthcare Test
  version: "1.0.0"
  author: Test
  description: Test healthcare contract
  effective_date: "2025-01-01"
  review_date: "2025-07-01"
  stakeholders: [CMO, DPO]
data_governance:
  allowed_input_classes: [phi, internal]
  allowed_output_classes: [internal, public]
  retention_period: P90D
  cross_border_transfer: false
rules:
  - id: HC-001
    description: PHI must not appear in outputs
    action: "*"
    conditions:
      - field: output.contains_phi
        operator: equals
        value: false
    on_violation: block
    tags: [hipaa, data-protection]
  - id: HC-002
    description: Clinical decisions need human-in-loop
    action: decide
    conditions:
      - field: metadata.human_in_loop
        operator: equals
        value: true
    on_violation: block
    tags: [safety]
  - id: HC-003
    description: Confidence above threshold
    action: recommend
    conditions:
      - field: output.confidence
        operator: greater_than
        value: 0.85
    on_violation: warn
    tags: [quality]
  - id: HC-004
    description: Caller needs clinician role
    action: [decide, recommend]
    conditions:
      - field: caller.roles
        operator: contains
        value: clinician
    on_violation: block
    tags: [access-control]
`;

describe("Compliance Reports", () => {
  let gov: GodClause;

  beforeEach(async () => {
    gov = new GodClause();
    gov.loadContractYAML(HEALTHCARE_CONTRACT);
    // Generate some audit entries
    await gov.evaluate({
      action: "generate",
      input: { prompt: "test" },
      output: { contains_phi: false },
      caller: { user_id: "u1", session_id: "s1", roles: ["clinician"] },
    });
    await gov.evaluate({
      action: "generate",
      input: { prompt: "bad" },
      output: { contains_phi: true },
      caller: { user_id: "u2", session_id: "s2", roles: ["user"] },
    });
  });

  it("generates EU AI Act report", () => {
    const report = generateComplianceReport(gov, "eu-ai-act");
    expect(report.framework).toBe("eu-ai-act");
    expect(report.controls.length).toBeGreaterThan(0);
    expect(report.contracts_evaluated).toBe(1);
    expect(report.audit_entries_evaluated).toBe(2);

    const art12 = report.controls.find((c) => c.control_id === "EU-AI-ACT-Art12");
    expect(art12).toBeDefined();
    expect(art12!.status).toBe("satisfied");
  });

  it("generates NIST AI RMF report", () => {
    const report = generateComplianceReport(gov, "nist-ai-rmf");
    expect(report.controls.length).toBeGreaterThan(0);
    const govern = report.controls.find((c) => c.control_id === "NIST-GOVERN-1");
    expect(govern!.status).toBe("satisfied");
  });

  it("generates SOC 2 report", () => {
    const report = generateComplianceReport(gov, "soc2");
    const access = report.controls.find((c) => c.control_id === "SOC2-CC6.1");
    expect(access!.status).toBe("satisfied"); // HC-004 checks roles
  });

  it("generates HIPAA report", () => {
    const report = generateComplianceReport(gov, "hipaa");
    const privacy = report.controls.find((c) => c.control_id === "HIPAA-Privacy");
    expect(privacy!.status).toBe("satisfied"); // HC-001 checks PHI
  });

  it("filters by date range", () => {
    const report = generateComplianceReport(gov, "eu-ai-act", {
      dateRange: { from: "2099-01-01", to: "2099-12-31" },
    });
    expect(report.audit_entries_evaluated).toBe(0);
  });
});

describe("Contract Linter", () => {
  it("warns on missing tags", () => {
    const contract = parseContract(`
      schema_version: "1.0"
      metadata:
        name: Test
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
        - id: R-001
          description: Test rule
          action: generate
          conditions:
            - field: output.ok
              operator: equals
              value: true
          on_violation: block
    `);
    const results = lintContract(contract);
    const tagWarning = results.find((r) => r.rule === "missing-tags");
    expect(tagWarning).toBeDefined();
  });

  it("errors on modify without obligations", () => {
    const contract = parseContract(`
      schema_version: "1.0"
      metadata:
        name: Test
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
        - id: R-001
          description: Test rule
          action: generate
          conditions:
            - field: output.ok
              operator: equals
              value: true
          on_violation: modify
    `);
    const results = lintContract(contract);
    const oblError = results.find((r) => r.rule === "modify-needs-obligations");
    expect(oblError).toBeDefined();
    expect(oblError!.severity).toBe("error");
  });

  it("errors on duplicate rule IDs", () => {
    const contract = parseContract(`
      schema_version: "1.0"
      metadata:
        name: Test
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
        - id: R-001
          description: First
          action: generate
          conditions:
            - field: output.ok
              operator: equals
              value: true
          on_violation: block
        - id: R-001
          description: Duplicate
          action: classify
          conditions:
            - field: output.ok
              operator: equals
              value: true
          on_violation: warn
    `);
    const results = lintContract(contract);
    const dupError = results.find((r) => r.rule === "duplicate-rule-id");
    expect(dupError).toBeDefined();
  });
});

describe("Audit Export", () => {
  it("exports CSV with headers and rows", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(HEALTHCARE_CONTRACT);
    await gov.evaluate({
      action: "generate",
      input: { prompt: "test" },
      output: { contains_phi: false },
      caller: { user_id: "u1", session_id: "s1", roles: ["user"] },
    });

    const entries = [...gov.getAuditEntries()];
    const csv = exportAuditCSV(entries);
    const lines = csv.split("\n");
    expect(lines[0]).toContain("entry_id");
    expect(lines.length).toBe(2); // header + 1 row
  });

  it("exports summary with analytics", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(HEALTHCARE_CONTRACT);
    await gov.evaluate({
      action: "generate",
      input: {},
      output: { contains_phi: false },
      caller: { user_id: "u1", session_id: "s1", roles: [] },
    });
    await gov.evaluate({
      action: "generate",
      input: {},
      output: { contains_phi: true },
      caller: { user_id: "u2", session_id: "s2", roles: [] },
    });

    const entries = [...gov.getAuditEntries()];
    const summary = exportAuditSummary(entries);
    expect(summary.total_decisions).toBe(2);
    expect(summary.permits + summary.denies + summary.modifies).toBe(2);
  });
});

describe("Decision Cache", () => {
  it("caches and returns decisions", async () => {
    const cache = new DecisionCache({ ttlMs: 10000 });
    const gov = new GodClause();
    gov.loadContractYAML(HEALTHCARE_CONTRACT);

    const ctx = {
      action: "generate" as const,
      input: { prompt: "test" },
      output: { contains_phi: false },
      caller: { user_id: "u1", session_id: "s1", roles: ["user"] },
    };

    expect(cache.get(ctx)).toBeUndefined();

    const decision = await gov.evaluate(ctx);
    cache.set(ctx, decision);

    const cached = cache.get(ctx);
    expect(cached).toBeDefined();
    expect(cached!.decision_id).toBe(decision.decision_id);
  });

  it("evicts expired entries", async () => {
    const cache = new DecisionCache({ ttlMs: 1 }); // 1ms TTL
    const gov = new GodClause();
    gov.loadContractYAML(HEALTHCARE_CONTRACT);

    const ctx = {
      action: "generate" as const,
      input: {},
      output: { contains_phi: false },
      caller: { user_id: "u1", session_id: "s1", roles: [] },
    };

    const decision = await gov.evaluate(ctx);
    cache.set(ctx, decision);

    await new Promise((r) => setTimeout(r, 10));
    expect(cache.get(ctx)).toBeUndefined();
  });

  it("clears all entries", async () => {
    const cache = new DecisionCache();
    const gov = new GodClause();
    gov.loadContractYAML(HEALTHCARE_CONTRACT);

    const ctx = {
      action: "generate" as const,
      input: {},
      output: { contains_phi: false },
      caller: { user_id: "u1", session_id: "s1", roles: [] },
    };

    cache.set(ctx, await gov.evaluate(ctx));
    expect(cache.size).toBe(1);

    cache.clear();
    expect(cache.size).toBe(0);
  });
});

describe("Contract ChangeLog", () => {
  it("records and queries changes", () => {
    const log = new ContractChangeLog();
    log.record({
      event_type: "registered",
      contract_name: "Test Policy",
      contract_version: "1.0.0",
      changed_by: "admin",
    });
    log.record({
      event_type: "activated",
      contract_name: "Test Policy",
      contract_version: "1.0.0",
    });

    const all = log.getAll();
    expect(all.length).toBe(2);

    const activations = log.query({ event_type: "activated" });
    expect(activations.length).toBe(1);

    const latest = log.getLatest("Test Policy");
    expect(latest!.event_type).toBe("activated");
  });
});

describe("Multi Audit Sink", () => {
  it("fans out to all sinks", () => {
    const sink1 = new MemoryAuditSink();
    const sink2 = new MemoryAuditSink();
    const multi = new MultiAuditSink([sink1, sink2]);

    const fakeEntry = { entry_id: "test" } as any;
    multi.append(fakeEntry);

    expect(sink1.entries.length).toBe(1);
    expect(sink2.entries.length).toBe(1);
  });
});
