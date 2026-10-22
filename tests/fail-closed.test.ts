import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "crypto";
import http from "http";
import {
  GodClause,
  ContractParseError,
  parseContract,
  packBundle,
  signBundle,
  verifyBundle,
  unpackBundle,
  createServer,
  MCPRouter,
} from "../src";
import type { PolicyContext, TrustContract } from "../src/types";

const base = {
  schema_version: "1.0",
  metadata: {
    name: "Fail Closed",
    version: "1.0.0",
    author: "Test",
    description: "Test",
    effective_date: "2026-01-01",
  },
  data_governance: {
    allowed_input_classes: ["public"],
    allowed_output_classes: ["public"],
    retention_period: "P30D",
    cross_border_transfer: false,
  },
};

function contractWith(conditions: unknown[]): string {
  return JSON.stringify({
    ...base,
    rules: [{ id: "R-1", description: "test", action: "generate", conditions, on_violation: "warn" }],
  });
}

const ctx: PolicyContext = {
  action: "generate",
  input: { prompt: "hello" },
  output: { text: "hi" },
  caller: { user_id: "u1", session_id: "s1", roles: [] },
};

describe("Fail closed: no contract loaded", () => {
  it("denies and audits the decision", async () => {
    const gov = new GodClause();

    const decision = await gov.evaluate(ctx);

    expect(decision.outcome).toBe("deny");
    expect(decision.blocks[0].rule_id).toBe("NO-CONTRACT");
    const entries = gov.getAuditEntries();
    expect(entries).toHaveLength(1);
    expect(entries[0].contract_name).toBe("(none)");
    expect(entries[0].allowed).toBe(false);
    expect(gov.verifyAuditChain().valid).toBe(true);
  });

  it("applies to tenants", async () => {
    const tenant = new GodClause().createTenant("t1");

    const decision = await tenant.evaluate(ctx);

    expect(decision.outcome).toBe("deny");
    expect(tenant.getAuditEntries()).toHaveLength(1);
  });
});

describe("Fail closed: rule that cannot be evaluated", () => {
  it("blocks with the error recorded, even for a warn rule", async () => {
    const gov = new GodClause();
    // Straight into the engine: every public loader rejects this regex at load time.
    gov.engine.loadContract(JSON.parse(contractWith([{ field: "input.prompt", operator: "matches", value: "(" }])));

    const decision = await gov.evaluate(ctx);

    expect(decision.outcome).toBe("deny");
    expect(decision.blocks[0].error).toContain("Invalid regular expression");
    expect(gov.getAuditEntries()[0].rule_results[0].error).toContain("Invalid regular expression");
  });

  it("blocks when a StateStore misbehaves, including an unstringifiable throw", async () => {
    const limited = contractWith([
      { field: "caller.user_id", operator: "rate_limit", value: { max: 5, window: "PT1H" } },
    ]);

    const nullStore = new GodClause({ stateStore: { recordAndCount: async () => null } as any });
    nullStore.loadContractYAML(limited);
    const d1 = await nullStore.evaluate(ctx);
    expect(d1.outcome).toBe("deny");
    expect(d1.blocks[0].error).toContain("instead of a number");

    const weirdThrow = new GodClause({
      stateStore: {
        recordAndCount: async () => {
          throw Object.create(null);
        },
      } as any,
    });
    weirdThrow.loadContractYAML(limited);
    const d2 = await weirdThrow.evaluate(ctx);
    expect(d2.outcome).toBe("deny");
    expect(d2.blocks[0].error).toBe("error could not be converted to text");
  });

  it("MCP router denies instead of skipping a permission whose condition throws", async () => {
    const router = new MCPRouter([
      {
        tool_pattern: "*",
        allowed: false,
        conditions: [{ field: "input.x", operator: "rate_limit", value: { max: 1, window: "PT1H" } }],
      },
      { tool_pattern: "*", allowed: true },
    ]);

    const result = await router.authorize({ tool_name: "shell.exec", arguments: {}, session_id: "s1" }, ctx);

    expect(result.allowed).toBe(false);
    expect(result.denial_reason).toContain("could not be evaluated");
  });
});

describe("Fail closed: load-time validation", () => {
  it("rejects an invalid or non-string regex", () => {
    for (const value of ["(", 42]) {
      expect(() => parseContract(contractWith([{ field: "input.prompt", operator: "matches", value }]))).toThrow(
        ContractParseError,
      );
    }
  });

  it("rejects malformed rate_limit values", () => {
    const bad = [null, "PT1H", { max: 5 }, { window: "PT1H" }, { max: 0, window: "PT1H" }, { max: 5, window: "1h" }];
    for (const value of [...bad, { max: 5, window: "PT0S" }, { max: 5, window: "P" }]) {
      expect(
        () => parseContract(contractWith([{ field: "caller.user_id", operator: "rate_limit", value }])),
        JSON.stringify(value),
      ).toThrow(ContractParseError);
    }
  });

  it("rejects wrong-typed operator values and non-finite limits", () => {
    const bad: unknown[][] = [
      [{ field: "output.score", operator: "greater_than", value: "0.8" }],
      [{ field: "output.score", operator: "less_than", value: null }],
      [{ field: "output.label", operator: "in", value: "hate" }],
      [{ field: "caller.user_id", operator: "rate_limit", value: { max: 1e309, window: "PT1H" } }],
      [{ field: "caller.user_id", operator: "rate_limit", value: { max: 0.5, window: "PT1H" } }],
    ];
    for (const conditions of bad) {
      expect(() => parseContract(contractWith(conditions)), JSON.stringify(conditions)).toThrow(ContractParseError);
    }
  });

  it("rejects rate_limit inside mcp_permissions, which the router cannot evaluate", () => {
    const source = JSON.stringify({
      ...base,
      rules: [],
      mcp_permissions: [
        {
          tool_pattern: "*",
          allowed: true,
          conditions: [{ field: "input.x", operator: "rate_limit", value: { max: 1, window: "PT1H" } }],
        },
      ],
    });
    expect(() => parseContract(source)).toThrow(ContractParseError);
  });

  it("validates objects given to loadContract like YAML input", () => {
    const bad = JSON.parse(contractWith([{ field: "input.prompt", operator: "matches", value: "(" }]));
    expect(() => new GodClause().loadContract(bad)).toThrow(ContractParseError);
    expect(() => new GodClause().createTenant("t").loadContract(bad)).toThrow(ContractParseError);
  });

  it("accepts valid values nested in all/any/not", () => {
    const source = contractWith([
      {
        all: [
          { not: { field: "input.prompt", operator: "matches", value: "^[a-z]+$" } },
          { any: [{ field: "caller.user_id", operator: "rate_limit", value: { max: 5, window: "PT1H" } }] },
        ],
      },
    ]);
    expect(() => parseContract(source)).not.toThrow();
  });

  it("names the path of the bad condition", () => {
    const source = contractWith([
      { field: "x", operator: "exists", value: true },
      { not: { field: "input.prompt", operator: "matches", value: "[" } },
    ]);
    let caught: unknown;
    try {
      parseContract(source);
    } catch (err) {
      caught = err;
    }
    expect((caught as ContractParseError).errors[0]).toMatch(/^\/rules\/0\/conditions\/1\/not\/value: /);
  });
});

describe("Fail closed: signed bundles", () => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  it("rejects a verified bundle whose contract fails the schema", () => {
    const bad = { ...JSON.parse(contractWith([])), rules: undefined } as TrustContract;
    const signed = signBundle(packBundle([bad]), { privateKey, keyId: "k1" });

    expect(() => verifyBundle(signed, { publicKey })).toThrow(ContractParseError);
    expect(() => unpackBundle(signed, { publicKey })).toThrow(ContractParseError);
  });

  it("rejects a verified bundle with an invalid regex", () => {
    const bad = JSON.parse(contractWith([{ field: "input.prompt", operator: "matches", value: "(" }]));
    const signed = signBundle(packBundle([bad]), { privateKey, keyId: "k1" });

    expect(() => unpackBundle(signed, { publicKey })).toThrow(ContractParseError);
  });

  it("rejects an envelope whose payloadType is not a bundle", () => {
    const good = JSON.parse(contractWith([{ field: "input.prompt", operator: "exists", value: true }]));
    const signed = signBundle(packBundle([good]), { privateKey, keyId: "k1" });
    signed.envelope.payloadType = "application/vnd.in-toto+json";

    expect(verifyBundle(signed, { publicKey }).valid).toBe(false);
  });

  it("still unpacks a valid bundle", () => {
    const good = JSON.parse(contractWith([{ field: "input.prompt", operator: "exists", value: true }]));
    const signed = signBundle(packBundle([good]), { privateKey, keyId: "k1" });

    expect(unpackBundle(signed, { publicKey })).toHaveLength(1);
  });
});

describe("Fail closed: REST server without contracts", () => {
  function request(method: string, path: string, body?: string): Promise<{ status: number; data: any }> {
    return new Promise((resolve, reject) => {
      const req = http.request(
        { hostname: "127.0.0.1", port: 3998, method, path, headers: { "Content-Type": "application/json" } },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode!, data: JSON.parse(Buffer.concat(chunks).toString()) }));
        },
      );
      req.on("error", reject);
      if (body) req.write(body);
      req.end();
    });
  }

  it("answers 503 on every decision route", async () => {
    const server = createServer({ port: 3998, logLevel: "error", contractsDir: "/nonexistent" });
    await server.start();
    try {
      expect((await request("GET", "/v1/ready")).status).toBe(503);
      for (const path of ["/v1/evaluate", "/v1/enforce", "/v1/evaluate/batch", "/v1/mcp/authorize"]) {
        const body = path.endsWith("batch") ? JSON.stringify({ contexts: [ctx] }) : JSON.stringify(ctx);
        const { status, data } = await request("POST", path, body);
        expect(status, path).toBe(503);
        expect(data.error).toBe("no_contracts");
      }
    } finally {
      await server.stop();
    }
  });
});
