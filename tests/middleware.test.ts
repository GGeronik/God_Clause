import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { GodClause, godClauseMiddleware, createAIHook, PolicyViolationError } from "../src";

const healthcareYAML = readFileSync(join(__dirname, "../examples/healthcare-ai.contract.yaml"), "utf-8");

function makeGov() {
  const gov = new GodClause();
  gov.loadContractYAML(healthcareYAML);
  return gov;
}

describe("HTTP Middleware", () => {
  function mockReqRes() {
    const req: any = {};
    const res: any = {
      statusCode: 200,
      headers: {} as Record<string, string>,
      body: "",
      setHeader(k: string, v: string) {
        this.headers[k] = v;
      },
      end(body: string) {
        this.body = body;
      },
    };
    return { req, res };
  }

  it("calls next() for compliant requests", async () => {
    const gov = makeGov();
    const middleware = godClauseMiddleware(gov, {
      contextExtractor: () => ({
        action: "recommend",
        input: { prompt: "test" },
        output: { contains_phi: false, confidence: 0.92, disclaimer_present: true },
        caller: { user_id: "dr-test", session_id: "s1", roles: ["clinician"] },
        metadata: { human_in_loop: true },
      }),
    });

    const { req, res } = mockReqRes();
    const next = vi.fn();
    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.godClauseDecision).toBeDefined();
    expect(req.godClauseDecision.allowed).toBe(true);
  });

  it("returns 403 for blocked requests", async () => {
    const gov = makeGov();
    const middleware = godClauseMiddleware(gov, {
      contextExtractor: () => ({
        action: "generate",
        input: {},
        output: { contains_phi: true, disclaimer_present: false },
        caller: { user_id: "u1", session_id: "s1", roles: ["viewer"] },
      }),
    });

    const { req, res } = mockReqRes();
    const next = vi.fn();
    await middleware(req, res, next);

    expect(next).not.toHaveBeenCalled();
    expect(res.statusCode).toBe(403);
    expect(res.body).toContain("Policy violation");
  });

  it("sets warning headers for warned requests", async () => {
    const gov = makeGov();
    const middleware = godClauseMiddleware(gov, {
      contextExtractor: () => ({
        action: "recommend",
        input: {},
        output: { contains_phi: false, confidence: 0.5, disclaimer_present: true },
        caller: { user_id: "dr-test", session_id: "s1", roles: ["clinician"] },
        metadata: { human_in_loop: true },
      }),
    });

    const { req, res } = mockReqRes();
    const next = vi.fn();
    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(res.headers["X-GodClause-Warnings"]).toContain("HC-003");
  });

  it("uses custom decisionKey", async () => {
    const gov = makeGov();
    const middleware = godClauseMiddleware(gov, {
      contextExtractor: () => ({
        action: "classify",
        input: {},
        caller: { user_id: "u1", session_id: "s1", roles: [] },
      }),
      decisionKey: "policyResult",
    });

    const { req, res } = mockReqRes();
    const next = vi.fn();
    await middleware(req, res, next);

    expect(req.policyResult).toBeDefined();
  });

  it("calls custom onBlock handler", async () => {
    const gov = makeGov();
    let customCalled = false;
    const middleware = godClauseMiddleware(gov, {
      contextExtractor: () => ({
        action: "generate",
        input: {},
        output: { contains_phi: true },
        caller: { user_id: "u1", session_id: "s1", roles: [] },
      }),
      onBlock: (res, decision) => {
        customCalled = true;
        res.statusCode = 451;
        res.end("Custom blocked");
      },
    });

    const { req, res } = mockReqRes();
    const next = vi.fn();
    await middleware(req, res, next);

    expect(customCalled).toBe(true);
    expect(res.statusCode).toBe(451);
  });
});

describe("AI Hook", () => {
  it("allows compliant pre-invocation", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(`
schema_version: "1.0"
metadata:
  name: Simple
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
    description: Input must have prompt
    action: generate
    conditions:
      - field: input.prompt
        operator: exists
        value: true
    on_violation: block
`);
    const hook = createAIHook(gov);

    const decision = await hook.beforeInvoke({
      prompt: "Hello",
      caller: { user_id: "u1", session_id: "s1", roles: [] },
    });
    expect(decision.allowed).toBe(true);
  });

  it("throws on blocked pre-invocation", async () => {
    const gov = new GodClause();
    gov.loadContractYAML(`
schema_version: "1.0"
metadata:
  name: Block Test
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
  - id: BT-001
    description: Block all
    action: generate
    conditions:
      - field: input.blocked
        operator: equals
        value: false
    on_violation: block
`);

    const hook = createAIHook(gov);
    await expect(
      hook.beforeInvoke({
        prompt: "test",
        caller: { user_id: "u1", session_id: "s1", roles: [] },
        metadata: {},
      }),
    ).rejects.toThrow(PolicyViolationError);
  });

  it("evaluates post-invocation context", async () => {
    const gov = makeGov();
    const hook = createAIHook(gov);

    const decision = await hook.afterInvoke({
      prompt: "Hello",
      response: { contains_phi: false, confidence: 0.95, disclaimer_present: true },
      caller: { user_id: "dr-test", session_id: "s1", roles: ["clinician"] },
      metadata: { human_in_loop: true },
    });
    expect(decision.allowed).toBe(true);
  });
});
