import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { createServer, GodClauseServer } from "../src/server/server";
import http from "http";

const TEST_CONTRACT = `
schema_version: "1.0"
metadata:
  name: Test Server Policy
  version: "1.0.0"
  author: Test
  description: Test contract for server
  effective_date: "2025-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: S-001
    description: Block high toxicity
    action: generate
    conditions:
      - field: output.toxicity
        operator: less_than
        value: 0.5
    on_violation: block
    tags: [safety]
`;

function request(method: string, path: string, body?: string): Promise<{ status: number; data: any }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: "127.0.0.1", port: 3999, method, path, headers: body ? { "Content-Type": "application/json" } : {} },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString();
          try {
            resolve({ status: res.statusCode!, data: JSON.parse(text) });
          } catch {
            resolve({ status: res.statusCode!, data: text });
          }
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

describe("REST API Server", () => {
  let server: GodClauseServer;

  beforeAll(async () => {
    server = createServer({ port: 3999, logLevel: "error" });
    await server.start();
    // Load a contract via API
    await new Promise<void>((resolve, reject) => {
      const req = http.request(
        { hostname: "127.0.0.1", port: 3999, method: "POST", path: "/v1/contracts", headers: { "Content-Type": "text/yaml" } },
        (res) => {
          res.on("data", () => {});
          res.on("end", resolve);
        },
      );
      req.on("error", reject);
      req.write(TEST_CONTRACT);
      req.end();
    });
  });

  afterAll(async () => {
    await server.stop();
  });

  it("GET /v1/health returns ok", async () => {
    const { status, data } = await request("GET", "/v1/health");
    expect(status).toBe(200);
    expect(data.status).toBe("ok");
  });

  it("GET /v1/ready returns ready with contracts", async () => {
    const { status, data } = await request("GET", "/v1/ready");
    expect(status).toBe(200);
    expect(data.ready).toBe(true);
    expect(data.contracts_loaded).toBeGreaterThan(0);
  });

  it("GET /v1/contracts lists active contracts", async () => {
    const { status, data } = await request("GET", "/v1/contracts");
    expect(status).toBe(200);
    expect(data.contracts.length).toBeGreaterThan(0);
    expect(data.contracts[0].name).toBe("Test Server Policy");
  });

  it("POST /v1/evaluate returns permit for compliant context", async () => {
    const { status, data } = await request("POST", "/v1/evaluate", JSON.stringify({
      action: "generate",
      input: { prompt: "hello" },
      output: { toxicity: 0.1 },
      caller: { user_id: "u1", session_id: "s1", roles: ["user"] },
    }));
    expect(status).toBe(200);
    expect(data.outcome).toBe("permit");
    expect(data.allowed).toBe(true);
  });

  it("POST /v1/evaluate returns deny for non-compliant context", async () => {
    const { status, data } = await request("POST", "/v1/evaluate", JSON.stringify({
      action: "generate",
      input: { prompt: "bad" },
      output: { toxicity: 0.9 },
      caller: { user_id: "u1", session_id: "s1", roles: ["user"] },
    }));
    expect(status).toBe(200);
    expect(data.outcome).toBe("deny");
    expect(data.allowed).toBe(false);
    expect(data.blocks.length).toBeGreaterThan(0);
  });

  it("POST /v1/enforce returns 403 on block", async () => {
    const { status, data } = await request("POST", "/v1/enforce", JSON.stringify({
      action: "generate",
      input: { prompt: "bad" },
      output: { toxicity: 0.9 },
      caller: { user_id: "u1", session_id: "s1", roles: ["user"] },
    }));
    expect(status).toBe(403);
    expect(data.error).toBe("policy_violation");
  });

  it("GET /v1/audit returns audit entries", async () => {
    const { status, data } = await request("GET", "/v1/audit");
    expect(status).toBe(200);
    expect(data.entries.length).toBeGreaterThan(0);
  });

  it("GET /v1/audit/verify returns valid chain", async () => {
    const { status, data } = await request("GET", "/v1/audit/verify");
    expect(status).toBe(200);
    expect(data.valid).toBe(true);
  });

  it("GET /v1/metrics returns prometheus format", async () => {
    const { status, data } = await request("GET", "/v1/metrics");
    expect(status).toBe(200);
    expect(data).toContain("godclause_decisions_total");
    expect(data).toContain("godclause_active_contracts");
  });

  it("POST /v1/evaluate/batch evaluates multiple contexts", async () => {
    const { status, data } = await request("POST", "/v1/evaluate/batch", JSON.stringify({
      contexts: [
        { action: "generate", input: {}, output: { toxicity: 0.1 }, caller: { user_id: "u1", session_id: "s1", roles: [] } },
        { action: "generate", input: {}, output: { toxicity: 0.9 }, caller: { user_id: "u2", session_id: "s2", roles: [] } },
      ],
    }));
    expect(status).toBe(200);
    expect(data.results.length).toBe(2);
    expect(data.results[0].allowed).toBe(true);
    expect(data.results[1].allowed).toBe(false);
  });

  it("GET /v1/unknown returns 404", async () => {
    const { status } = await request("GET", "/v1/unknown");
    expect(status).toBe(404);
  });
});
