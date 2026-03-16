import { describe, it, expect } from "vitest";
import { GodClause, MemoryStateStore, parseISO8601Duration, PolicyContext } from "../src";

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "generate",
    input: { prompt: "test" },
    caller: { user_id: "alice", session_id: "s1", roles: [] },
    ...overrides,
  };
}

const rateLimitContract = `
schema_version: "1.0"
metadata:
  name: Rate Limit Test
  version: "1.0.0"
  author: Test
  description: Test rate limiting
  effective_date: "2026-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: RL-001
    description: Max 3 requests per hour per user
    action: generate
    conditions:
      - field: caller.user_id
        operator: rate_limit
        value:
          max: 3
          window: PT1H
    on_violation: block
`;

describe("Rate Limiting", () => {
  it("allows requests within rate limit", async () => {
    const store = new MemoryStateStore();
    const gov = new GodClause({ stateStore: store });
    gov.loadContractYAML(rateLimitContract);

    const d1 = await gov.evaluate(makeCtx());
    expect(d1.allowed).toBe(true);

    const d2 = await gov.evaluate(makeCtx());
    expect(d2.allowed).toBe(true);

    const d3 = await gov.evaluate(makeCtx());
    expect(d3.allowed).toBe(true);
  });

  it("blocks requests exceeding rate limit", async () => {
    const store = new MemoryStateStore();
    const gov = new GodClause({ stateStore: store });
    gov.loadContractYAML(rateLimitContract);

    for (let i = 0; i < 3; i++) {
      await gov.evaluate(makeCtx());
    }

    const d4 = await gov.evaluate(makeCtx());
    expect(d4.allowed).toBe(false);
    expect(d4.blocks[0].rule_id).toBe("RL-001");
  });

  it("tracks different users independently", async () => {
    const store = new MemoryStateStore();
    const gov = new GodClause({ stateStore: store });
    gov.loadContractYAML(rateLimitContract);

    for (let i = 0; i < 3; i++) {
      await gov.evaluate(makeCtx({ caller: { user_id: "alice", session_id: "s1", roles: [] } }));
    }

    // Alice is now rate limited
    const aliceD = await gov.evaluate(makeCtx({ caller: { user_id: "alice", session_id: "s1", roles: [] } }));
    expect(aliceD.allowed).toBe(false);

    // Bob should still be allowed
    const bobD = await gov.evaluate(makeCtx({ caller: { user_id: "bob", session_id: "s2", roles: [] } }));
    expect(bobD.allowed).toBe(true);
  });

  it("throws without state store", async () => {
    const gov = new GodClause(); // no stateStore
    gov.loadContractYAML(rateLimitContract);

    await expect(gov.evaluate(makeCtx())).rejects.toThrow("StateStore");
  });

  it("clears state store", async () => {
    const store = new MemoryStateStore();
    const gov = new GodClause({ stateStore: store });
    gov.loadContractYAML(rateLimitContract);

    for (let i = 0; i < 4; i++) {
      await gov.evaluate(makeCtx());
    }

    await store.clear();

    const d = await gov.evaluate(makeCtx());
    expect(d.allowed).toBe(true);
  });

  it("skips rate limit rules for non-matching actions", async () => {
    const store = new MemoryStateStore();
    const gov = new GodClause({ stateStore: store });
    gov.loadContractYAML(rateLimitContract);

    // Action is "classify" not "generate", so RL-001 shouldn't apply
    const d = await gov.evaluate(makeCtx({ action: "classify" }));
    expect(d.allowed).toBe(true);
  });
});

describe("ISO 8601 Duration Parser", () => {
  it("parses hours", () => {
    expect(parseISO8601Duration("PT1H")).toBe(3600000);
  });

  it("parses minutes", () => {
    expect(parseISO8601Duration("PT30M")).toBe(1800000);
  });

  it("parses seconds", () => {
    expect(parseISO8601Duration("PT5S")).toBe(5000);
  });

  it("parses combined", () => {
    expect(parseISO8601Duration("PT1H30M15S")).toBe(5415000);
  });

  it("parses days", () => {
    expect(parseISO8601Duration("P1D")).toBe(86400000);
  });

  it("parses days + time", () => {
    expect(parseISO8601Duration("P7DT12H")).toBe(648000000);
  });

  it("throws on invalid", () => {
    expect(() => parseISO8601Duration("invalid")).toThrow("Invalid ISO 8601 duration");
  });
});
