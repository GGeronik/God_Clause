import { describe, it, expect, beforeAll, afterAll } from "vitest";
import http from "http";
import { createServer, GodClauseServer } from "../src/server/server";

const PORT = 3997;
const TOKEN = "t0ken-for-tests";

const CONTRACT = `
schema_version: "1.0"
metadata:
  name: Hardening
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
  - id: H-001
    description: Prompt must exist
    action: generate
    conditions:
      - field: input.prompt
        operator: exists
        value: true
    on_violation: block
mcp_permissions:
  - tool_pattern: web_search
    allowed: true
    max_calls_per_session: 2
`;

const ctx = { action: "generate", input: { prompt: "hi" }, caller: { user_id: "u", session_id: "s", roles: [] } };

function request(
  method: string,
  path: string,
  body?: string,
  headers: Record<string, string> = {},
): Promise<{ status: number; data: any; headers: http.IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: "127.0.0.1", port: PORT, method, path, headers: { "Content-Type": "application/json", ...headers } },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString();
          let data: any = text;
          try {
            data = JSON.parse(text);
          } catch {
            /* plain text body */
          }
          resolve({ status: res.statusCode!, data, headers: res.headers });
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

const auth = { Authorization: `Bearer ${TOKEN}` };

describe("REST server hardening", () => {
  let server: GodClauseServer;

  beforeAll(async () => {
    server = createServer({ port: PORT, logLevel: "error", apiToken: TOKEN, maxBodyBytes: 64 * 1024 });
    server.gov.loadContractYAML(CONTRACT);
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  it("probes need no token", async () => {
    expect((await request("GET", "/v1/health")).status).toBe(200);
    expect((await request("GET", "/v1/ready")).status).toBe(200);
  });

  it("everything else needs the exact bearer token", async () => {
    const missing = await request("POST", "/v1/evaluate", JSON.stringify(ctx));
    expect(missing.status).toBe(401);
    expect(missing.headers["www-authenticate"]).toBe("Bearer");
    expect(missing.data.error).toBe("unauthorized");

    expect((await request("GET", "/v1/contracts", undefined, { Authorization: "Bearer wrong" })).status).toBe(401);
    expect((await request("GET", "/v1/contracts", undefined, { Authorization: `Bearer ${TOKEN}x` })).status).toBe(401);
    expect((await request("POST", "/v1/contracts", CONTRACT, { "Content-Type": "text/yaml" })).status).toBe(401);
    expect((await request("GET", "/v1/metrics", undefined, {})).status).toBe(401);

    const ok = await request("POST", "/v1/evaluate", JSON.stringify(ctx), auth);
    expect(ok.status).toBe(200);
    expect(ok.data.outcome).toBe("permit");

    const lower = await request("GET", "/v1/contracts", undefined, { Authorization: `bearer ${TOKEN}` });
    expect(lower.status).toBe(200);
  });

  it("enforces max_calls_per_session on /v1/mcp/authorize", async () => {
    const call = (session_id: unknown) =>
      request("POST", "/v1/mcp/authorize", JSON.stringify({ tool_name: "web_search", session_id }), auth);
    expect((await call("s1")).status).toBe(200);
    expect((await call("s1")).status).toBe(200);
    const third = await call("s1");
    expect(third.status).toBe(403);
    expect(third.data.denial_reason).toContain("Rate limit");
    expect(third.data.decision_id).toBeDefined();
    expect((await call("s2")).status).toBe(200);
    expect((await call({ a: 1 })).status).toBe(400);

    // Every authorization went through evaluate(), so it is in the audit chain.
    const audited = server.gov.getAuditEntries().filter((e) => e.action === "mcp_call");
    expect(audited.length).toBe(4);
    expect(audited.filter((e) => !e.allowed).map((e) => e.blocks)).toEqual([["MCP-PERMISSIONS"]]);
  });

  it("validates query strings and options instead of crashing", async () => {
    expect((await request("GET", "/v1/audit?allowed=TRUE&limit=abc&offset=-1", undefined, auth)).status).toBe(200);
    expect((await request("GET", "/v1/audit?from=yesterday", undefined, auth)).status).toBe(400);
    expect((await request("PUT", "/v1/contracts/%E0%A4%A/activate/1", undefined, auth)).status).toBe(400);
    const badTags = JSON.stringify({ ...ctx, options: { includeTags: { length: 1 } } });
    expect((await request("POST", "/v1/evaluate", badTags, auth)).status).toBe(400);
    const nullEntry = JSON.stringify({ audit_entries: [null], merkle_seals: [] });
    expect((await request("POST", "/v1/proof-bundle/verify", nullEntry, auth)).status).toBe(400);
  });

  it("rejects a body over the limit with 413", async () => {
    const big = JSON.stringify({ ...ctx, input: { prompt: "x".repeat(70 * 1024) } });
    const { status, data } = await request("POST", "/v1/evaluate", big, auth);
    expect(status).toBe(413);
    expect(data.error).toBe("payload_too_large");

    expect((await request("POST", "/v1/evaluate", JSON.stringify(ctx), auth)).status).toBe(200);
  });

  it("answers 400, not 500, for bad input", async () => {
    const cases: Array<[string, string]> = [
      ["/v1/evaluate", "{"],
      ["/v1/evaluate", JSON.stringify({ input: {} })],
      ["/v1/evaluate", JSON.stringify({ action: "generate", caller: { user_id: "u" } })],
      ["/v1/enforce", JSON.stringify({ action: "", caller: ctx.caller })],
      ["/v1/evaluate/batch", JSON.stringify({ contexts: [ctx, { action: "generate" }] })],
      ["/v1/evaluate/batch", JSON.stringify({ contexts: "nope" })],
      ["/v1/mcp/authorize", JSON.stringify({ arguments: {} })],
      ["/v1/proof-bundle/verify", JSON.stringify({ hello: "world" })],
    ];
    for (const [path, body] of cases) {
      const { status, data } = await request("POST", path, body, auth);
      expect(status, `${path} ${body}`).toBe(400);
      expect(["invalid_json", "invalid_request"], `${path} ${body}`).toContain(data.error);
    }
  });
});

describe("REST server without a token", () => {
  it("treats a blank API_TOKEN as unset and serves unauthenticated", async () => {
    const server = createServer({ port: PORT + 1, logLevel: "error", apiToken: "", hmacSecret: "" });
    server.gov.loadContractYAML(CONTRACT);
    await server.start();
    try {
      const res = await new Promise<number>((resolve, reject) => {
        http
          .get({ hostname: "127.0.0.1", port: PORT + 1, path: "/v1/contracts" }, (r) => {
            r.resume();
            resolve(r.statusCode!);
          })
          .on("error", reject);
      });
      expect(res).toBe(200);
    } finally {
      await server.stop();
    }
  });
});
