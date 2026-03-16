import { describe, it, expect, beforeEach } from "vitest";
import { MCPRouter, globMatch } from "../src/engine/mcp-router";
import { MemoryStateStore } from "../src/engine/state-store";
import type {
  MCPPermission,
  MCPToolCall,
  PolicyContext,
} from "../src/types";

// ─── Helpers ────────────────────────────────────────────────────────

function makeCtx(overrides: Partial<PolicyContext> = {}): PolicyContext {
  return {
    action: "generate",
    input: { prompt: "test" },
    caller: {
      user_id: "user-1",
      session_id: "sess-1",
      roles: ["admin"],
    },
    ...overrides,
  };
}

function makeCall(overrides: Partial<MCPToolCall> = {}): MCPToolCall {
  return {
    tool_name: "file_read",
    arguments: {},
    session_id: "sess-1",
    ...overrides,
  };
}

// ─── globMatch unit tests ───────────────────────────────────────────

describe("globMatch", () => {
  it("matches exact tool names", () => {
    expect(globMatch("database.query", "database.query")).toBe(true);
    expect(globMatch("database.query", "database.insert")).toBe(false);
  });

  it("matches wildcard prefix patterns", () => {
    expect(globMatch("file_*", "file_read")).toBe(true);
    expect(globMatch("file_*", "file_write")).toBe(true);
    expect(globMatch("file_*", "file_")).toBe(true);
    expect(globMatch("file_*", "database_read")).toBe(false);
  });

  it("matches universal wildcard", () => {
    expect(globMatch("*", "anything")).toBe(true);
    expect(globMatch("*", "file_read")).toBe(true);
    expect(globMatch("*", "")).toBe(true);
  });

  it("matches wildcard in the middle", () => {
    expect(globMatch("db_*_query", "db_user_query")).toBe(true);
    expect(globMatch("db_*_query", "db_order_query")).toBe(true);
    expect(globMatch("db_*_query", "db_query")).toBe(false);
  });

  it("matches suffix wildcards", () => {
    expect(globMatch("*_read", "file_read")).toBe(true);
    expect(globMatch("*_read", "db_read")).toBe(true);
    expect(globMatch("*_read", "file_write")).toBe(false);
  });
});

// ─── MCPRouter tests ────────────────────────────────────────────────

describe("MCPRouter", () => {
  it("allows exact tool name match", async () => {
    const router = new MCPRouter([
      { tool_pattern: "file_read", allowed: true },
    ]);
    const result = await router.authorize(makeCall(), makeCtx());
    expect(result.allowed).toBe(true);
  });

  it("allows wildcard match (file_* matches file_read)", async () => {
    const router = new MCPRouter([
      { tool_pattern: "file_*", allowed: true },
    ]);
    const result = await router.authorize(makeCall({ tool_name: "file_read" }), makeCtx());
    expect(result.allowed).toBe(true);
    expect(result.matched_permission?.tool_pattern).toBe("file_*");
  });

  it("allows universal wildcard (* matches everything)", async () => {
    const router = new MCPRouter([
      { tool_pattern: "*", allowed: true },
    ]);
    const result = await router.authorize(makeCall({ tool_name: "some_random_tool" }), makeCtx());
    expect(result.allowed).toBe(true);
  });

  it("uses first-match-wins ordering", async () => {
    const router = new MCPRouter([
      { tool_pattern: "file_read", allowed: false },
      { tool_pattern: "file_*", allowed: true },
    ]);
    // file_read matches the first (deny) rule, not the second (allow) rule
    const result = await router.authorize(makeCall({ tool_name: "file_read" }), makeCtx());
    expect(result.allowed).toBe(false);

    // file_write skips the first rule, matches the second (allow)
    const result2 = await router.authorize(makeCall({ tool_name: "file_write" }), makeCtx());
    expect(result2.allowed).toBe(true);
  });

  it("defaults to deny when no permission matches (fail-closed)", async () => {
    const router = new MCPRouter([
      { tool_pattern: "file_*", allowed: true },
    ]);
    const result = await router.authorize(makeCall({ tool_name: "database_query" }), makeCtx());
    expect(result.allowed).toBe(false);
    expect(result.denial_reason).toContain("No permission rule matches");
    expect(result.denial_reason).toContain("fail-closed");
  });

  it("forwards require_human_approval flag", async () => {
    const router = new MCPRouter([
      { tool_pattern: "dangerous_*", allowed: true, require_human_approval: true },
    ]);
    const result = await router.authorize(makeCall({ tool_name: "dangerous_delete" }), makeCtx());
    expect(result.allowed).toBe(true);
    expect(result.require_human_approval).toBe(true);
  });

  it("defaults require_human_approval to false when not set", async () => {
    const router = new MCPRouter([
      { tool_pattern: "*", allowed: true },
    ]);
    const result = await router.authorize(makeCall(), makeCtx());
    expect(result.require_human_approval).toBe(false);
  });

  it("forwards audit_level from matched permission", async () => {
    const router = new MCPRouter([
      { tool_pattern: "file_*", allowed: true, audit_level: "summary" },
    ]);
    const result = await router.authorize(makeCall(), makeCtx());
    expect(result.audit_level).toBe("summary");
  });

  it("defaults audit_level to full when not specified", async () => {
    const router = new MCPRouter([
      { tool_pattern: "*", allowed: true },
    ]);
    const result = await router.authorize(makeCall(), makeCtx());
    expect(result.audit_level).toBe("full");
  });

  it("forwards audit_level 'none'", async () => {
    const router = new MCPRouter([
      { tool_pattern: "logging_*", allowed: true, audit_level: "none" },
    ]);
    const result = await router.authorize(makeCall({ tool_name: "logging_info" }), makeCtx());
    expect(result.audit_level).toBe("none");
  });

  it("provides denial_reason when tool is explicitly denied", async () => {
    const router = new MCPRouter([
      { tool_pattern: "admin_*", allowed: false },
    ]);
    const result = await router.authorize(makeCall({ tool_name: "admin_reset" }), makeCtx());
    expect(result.allowed).toBe(false);
    expect(result.denial_reason).toContain("denied by permission rule");
    expect(result.denial_reason).toContain("admin_*");
  });

  it("enforces session rate limiting with max_calls_per_session", async () => {
    const store = new MemoryStateStore();
    const router = new MCPRouter(
      [{ tool_pattern: "api_*", allowed: true, max_calls_per_session: 3 }],
      store,
    );
    const ctx = makeCtx();

    // First 3 calls should succeed
    for (let i = 0; i < 3; i++) {
      const result = await router.authorize(makeCall({ tool_name: "api_fetch", session_id: "s1" }), ctx);
      expect(result.allowed).toBe(true);
    }

    // 4th call should be denied
    const result = await router.authorize(makeCall({ tool_name: "api_fetch", session_id: "s1" }), ctx);
    expect(result.allowed).toBe(false);
    expect(result.denial_reason).toContain("Rate limit exceeded");
  });

  it("rate limits are per-session (different sessions independent)", async () => {
    const store = new MemoryStateStore();
    const router = new MCPRouter(
      [{ tool_pattern: "api_*", allowed: true, max_calls_per_session: 1 }],
      store,
    );
    const ctx = makeCtx();

    const r1 = await router.authorize(makeCall({ tool_name: "api_fetch", session_id: "s1" }), ctx);
    expect(r1.allowed).toBe(true);

    // Same session — should be denied
    const r2 = await router.authorize(makeCall({ tool_name: "api_fetch", session_id: "s1" }), ctx);
    expect(r2.allowed).toBe(false);

    // Different session — should succeed
    const r3 = await router.authorize(makeCall({ tool_name: "api_fetch", session_id: "s2" }), ctx);
    expect(r3.allowed).toBe(true);
  });

  it("skips rate limiting when no state store is provided", async () => {
    const router = new MCPRouter([
      { tool_pattern: "api_*", allowed: true, max_calls_per_session: 1 },
    ]);

    // Without a state store, rate limiting is not enforced
    const r1 = await router.authorize(makeCall({ tool_name: "api_fetch" }), makeCtx());
    expect(r1.allowed).toBe(true);
    const r2 = await router.authorize(makeCall({ tool_name: "api_fetch" }), makeCtx());
    expect(r2.allowed).toBe(true);
  });

  it("handles multiple permissions with mixed allow/deny", async () => {
    const permissions: MCPPermission[] = [
      { tool_pattern: "file_delete", allowed: false },
      { tool_pattern: "file_*", allowed: true, audit_level: "summary" },
      { tool_pattern: "admin_*", allowed: false },
      { tool_pattern: "*", allowed: true, require_human_approval: true },
    ];
    const router = new MCPRouter(permissions);
    const ctx = makeCtx();

    // file_delete -> denied by first rule
    const r1 = await router.authorize(makeCall({ tool_name: "file_delete" }), ctx);
    expect(r1.allowed).toBe(false);

    // file_read -> allowed by second rule
    const r2 = await router.authorize(makeCall({ tool_name: "file_read" }), ctx);
    expect(r2.allowed).toBe(true);
    expect(r2.audit_level).toBe("summary");

    // admin_reset -> denied by third rule
    const r3 = await router.authorize(makeCall({ tool_name: "admin_reset" }), ctx);
    expect(r3.allowed).toBe(false);

    // random_tool -> allowed by catch-all with human approval
    const r4 = await router.authorize(makeCall({ tool_name: "random_tool" }), ctx);
    expect(r4.allowed).toBe(true);
    expect(r4.require_human_approval).toBe(true);
  });

  it("evaluates conditions and skips permission when conditions fail", async () => {
    const router = new MCPRouter([
      {
        tool_pattern: "file_*",
        allowed: true,
        conditions: [
          { field: "caller.roles", operator: "contains", value: "admin" },
        ],
      },
      { tool_pattern: "*", allowed: false },
    ]);

    // Admin role -> conditions pass, allowed
    const r1 = await router.authorize(makeCall(), makeCtx({ caller: { user_id: "u1", session_id: "s1", roles: ["admin"] } }));
    expect(r1.allowed).toBe(true);

    // Non-admin -> conditions fail, falls through to deny-all
    const r2 = await router.authorize(makeCall(), makeCtx({ caller: { user_id: "u2", session_id: "s2", roles: ["viewer"] } }));
    expect(r2.allowed).toBe(false);
  });

  it("returns matched_permission in the result", async () => {
    const perm: MCPPermission = {
      tool_pattern: "file_*",
      allowed: true,
      audit_level: "summary",
      require_human_approval: true,
    };
    const router = new MCPRouter([perm]);
    const result = await router.authorize(makeCall(), makeCtx());
    expect(result.matched_permission).toEqual(perm);
  });
});
