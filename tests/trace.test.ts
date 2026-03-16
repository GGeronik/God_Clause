import { describe, it, expect } from "vitest";
import { GodClause, TraceBuilder, PolicyContext } from "../src";

const simpleContract = `
schema_version: "1.0"
metadata:
  name: Trace Test
  version: "1.0.0"
  author: Test
  description: Test tracing
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: TR-001
    description: Allow all
    action: "*"
    conditions:
      - field: input.prompt
        operator: exists
        value: true
    on_violation: warn
`;

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "generate",
    input: { prompt: "test" },
    caller: { user_id: "u1", session_id: "s1", roles: [] },
    ...overrides,
  };
}

describe("TraceBuilder", () => {
  it("creates root spans", () => {
    const builder = new TraceBuilder();
    const root = builder.rootSpan("agent_run");
    expect(root.trace_id).toBe(builder.traceId);
    expect(root.span_id).toBeDefined();
    expect(root.parent_span_id).toBeUndefined();
    expect(root.span_type).toBe("agent_run");
  });

  it("creates child spans linked to parent", () => {
    const builder = new TraceBuilder();
    const root = builder.rootSpan();
    const child = builder.childSpan(root, "model_call");
    expect(child.trace_id).toBe(builder.traceId);
    expect(child.parent_span_id).toBe(root.span_id);
    expect(child.span_type).toBe("model_call");
  });

  it("uses provided trace ID", () => {
    const builder = new TraceBuilder("custom-trace-id");
    expect(builder.traceId).toBe("custom-trace-id");
    const span = builder.rootSpan();
    expect(span.trace_id).toBe("custom-trace-id");
  });

  it("generates unique span IDs", () => {
    const builder = new TraceBuilder();
    const span1 = builder.rootSpan();
    const span2 = builder.rootSpan();
    expect(span1.span_id).not.toBe(span2.span_id);
  });
});

describe("Trace Context in Audit", () => {
  it("records trace fields in audit entries", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(simpleContract);

    const builder = new TraceBuilder("trace-123");
    const span = builder.rootSpan("agent_run");

    await gov.evaluate(makeCtx({ trace: span }));

    const entries = gov.getAuditEntries();
    expect(entries[0].trace_id).toBe("trace-123");
    expect(entries[0].span_id).toBe(span.span_id);
    expect(entries[0].parent_span_id).toBeUndefined();
  });

  it("records parent_span_id for child spans", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(simpleContract);

    const builder = new TraceBuilder();
    const root = builder.rootSpan();
    const child = builder.childSpan(root, "model_call");

    await gov.evaluate(makeCtx({ trace: child }));

    const entries = gov.getAuditEntries();
    expect(entries[0].parent_span_id).toBe(root.span_id);
  });

  it("queries audit by trace_id", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(simpleContract);

    const builder1 = new TraceBuilder("trace-A");
    const builder2 = new TraceBuilder("trace-B");

    await gov.evaluate(makeCtx({ trace: builder1.rootSpan() }));
    await gov.evaluate(makeCtx({ trace: builder2.rootSpan() }));
    await gov.evaluate(makeCtx({ trace: builder1.rootSpan() }));

    const traceA = gov.queryAudit({ trace_id: "trace-A" });
    expect(traceA).toHaveLength(2);
  });

  it("queries audit by parent_span_id", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(simpleContract);

    const builder = new TraceBuilder();
    const root = builder.rootSpan();
    const child1 = builder.childSpan(root);
    const child2 = builder.childSpan(root);

    await gov.evaluate(makeCtx({ trace: root }));
    await gov.evaluate(makeCtx({ trace: child1 }));
    await gov.evaluate(makeCtx({ trace: child2 }));

    const children = gov.queryAudit({ parent_span_id: root.span_id });
    expect(children).toHaveLength(2);
  });
});
