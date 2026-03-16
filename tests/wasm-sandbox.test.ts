import { describe, it, expect } from "vitest";
import {
  WasmPolicySandbox,
  createMinimalWasmModule,
  createFailingWasmModule,
  createMemoryHogModule,
} from "../src/sandbox/wasm-sandbox";
import type { PolicyContext } from "../src/types";

// ─── Helpers ─────────────────────────────────────────────────────────

function makeContext(overrides?: Partial<PolicyContext>): PolicyContext {
  return {
    action: "generate",
    input: { prompt: "hello" },
    caller: { user_id: "u1", session_id: "s1", roles: ["admin"] },
    ...overrides,
  };
}

// ─── Tests ───────────────────────────────────────────────────────────

describe("WasmPolicySandbox", () => {
  // ── Module lifecycle ────────────────────────────────────────────────

  describe("Module lifecycle", () => {
    it("loadModule with valid WASM bytes returns a module ID", () => {
      const sandbox = new WasmPolicySandbox();
      const id = sandbox.loadModule(createMinimalWasmModule());
      expect(id).toBeDefined();
      expect(typeof id).toBe("string");
      expect(id.length).toBeGreaterThan(0);
    });

    it("loadModule rejects invalid bytes", () => {
      const sandbox = new WasmPolicySandbox();
      expect(() => sandbox.loadModule(new Uint8Array([0x00, 0x01]))).toThrow(/Failed to compile WASM module/);
    });

    it("unloadModule removes the module", () => {
      const sandbox = new WasmPolicySandbox();
      const id = sandbox.loadModule(createMinimalWasmModule());
      expect(sandbox.getModuleCount()).toBe(1);
      sandbox.unloadModule(id);
      expect(sandbox.getModuleCount()).toBe(0);
    });

    it("unloadModule on unknown ID throws", () => {
      const sandbox = new WasmPolicySandbox();
      expect(() => sandbox.unloadModule("nonexistent")).toThrow(/not found/);
    });

    it("getModuleCount tracks loaded modules", () => {
      const sandbox = new WasmPolicySandbox();
      expect(sandbox.getModuleCount()).toBe(0);
      const id1 = sandbox.loadModule(createMinimalWasmModule());
      expect(sandbox.getModuleCount()).toBe(1);
      const id2 = sandbox.loadModule(createMinimalWasmModule());
      expect(sandbox.getModuleCount()).toBe(2);
      sandbox.unloadModule(id1);
      expect(sandbox.getModuleCount()).toBe(1);
      sandbox.unloadModule(id2);
      expect(sandbox.getModuleCount()).toBe(0);
    });
  });

  // ── Evaluation ──────────────────────────────────────────────────────

  describe("Evaluation", () => {
    it("evaluate with passing module returns { passed: true, violations: [] }", async () => {
      const sandbox = new WasmPolicySandbox();
      const id = sandbox.loadModule(createMinimalWasmModule());
      const result = await sandbox.evaluate(id, makeContext());
      expect(result.passed).toBe(true);
      expect(result.violations).toEqual([]);
    });

    it("evaluate with failing module returns { passed: false, violations: [...] }", async () => {
      const sandbox = new WasmPolicySandbox();
      const id = sandbox.loadModule(createFailingWasmModule());
      const result = await sandbox.evaluate(id, makeContext());
      expect(result.passed).toBe(false);
      expect(result.violations.length).toBeGreaterThan(0);
    });

    it("evaluate with unknown moduleId throws", async () => {
      const sandbox = new WasmPolicySandbox();
      await expect(sandbox.evaluate("nonexistent", makeContext())).rejects.toThrow(/not found/);
    });
  });

  // ── Obligation execution ────────────────────────────────────────────

  describe("Obligation execution", () => {
    it("executeObligation with valid module returns { success: true }", async () => {
      const sandbox = new WasmPolicySandbox();
      const id = sandbox.loadModule(createMinimalWasmModule());
      const result = await sandbox.executeObligation(id, { key: "value" });
      expect(result.success).toBe(true);
    });

    it("executeObligation with unknown moduleId throws", async () => {
      const sandbox = new WasmPolicySandbox();
      await expect(sandbox.executeObligation("nonexistent", {})).rejects.toThrow(/not found/);
    });
  });

  // ── Resource limits ─────────────────────────────────────────────────

  describe("Resource limits", () => {
    it("loadModule rejects when maxModules exceeded", () => {
      const sandbox = new WasmPolicySandbox({ maxModules: 2 });
      sandbox.loadModule(createMinimalWasmModule());
      sandbox.loadModule(createMinimalWasmModule());
      expect(() => sandbox.loadModule(createMinimalWasmModule())).toThrow(/Maximum module limit reached/);
    });

    it("memory limit: module cannot exceed maxMemoryPages", () => {
      // Create sandbox with very small memory limit (2 pages = 128KB)
      const sandbox = new WasmPolicySandbox({ maxMemoryPages: 2 });
      const id = sandbox.loadModule(createMemoryHogModule(100));
      // The module loads fine, but grow_memory should fail (return -1)
      const growFn = (sandbox as any).modules.get(id).instance.exports.grow_memory as () => number;
      const growResult = growFn();
      // -1 means memory.grow failed due to limits
      expect(growResult).toBe(-1);
    });
  });

  // ── Resource tracking ───────────────────────────────────────────────

  describe("Resource tracking", () => {
    it("getResourceUsage returns valid stats after evaluation", async () => {
      const sandbox = new WasmPolicySandbox();
      const id = sandbox.loadModule(createMinimalWasmModule());
      await sandbox.evaluate(id, makeContext());
      const usage = sandbox.getResourceUsage(id);
      expect(usage.memoryBytes).toBeGreaterThan(0);
      expect(usage.executionCount).toBe(1);
      expect(usage.lastExecutionMs).toBeGreaterThanOrEqual(0);
    });

    it("getResourceUsage tracks execution count", async () => {
      const sandbox = new WasmPolicySandbox();
      const id = sandbox.loadModule(createMinimalWasmModule());
      await sandbox.evaluate(id, makeContext());
      await sandbox.evaluate(id, makeContext());
      await sandbox.evaluate(id, makeContext());
      const usage = sandbox.getResourceUsage(id);
      expect(usage.executionCount).toBe(3);
    });

    it("getResourceUsage tracks memory bytes", () => {
      const sandbox = new WasmPolicySandbox();
      const id = sandbox.loadModule(createMinimalWasmModule());
      const usage = sandbox.getResourceUsage(id);
      // 1 initial page = 64KB
      expect(usage.memoryBytes).toBe(65536);
    });
  });

  // ── Isolation ───────────────────────────────────────────────────────

  describe("Isolation", () => {
    it("context is frozen during evaluation (cannot be mutated by WASM)", async () => {
      const sandbox = new WasmPolicySandbox();
      const id = sandbox.loadModule(createMinimalWasmModule());
      const ctx = makeContext();
      const inputRef = ctx.input;
      await sandbox.evaluate(id, ctx);
      // Context should not have been modified
      expect(ctx.input).toBe(inputRef);
      expect(ctx.input.prompt).toBe("hello");
    });

    it("multiple modules are isolated from each other", async () => {
      const sandbox = new WasmPolicySandbox();
      const passingId = sandbox.loadModule(createMinimalWasmModule());
      const failingId = sandbox.loadModule(createFailingWasmModule());

      const passResult = await sandbox.evaluate(passingId, makeContext());
      const failResult = await sandbox.evaluate(failingId, makeContext());

      expect(passResult.passed).toBe(true);
      expect(failResult.passed).toBe(false);

      // Each module has independent usage stats
      const passUsage = sandbox.getResourceUsage(passingId);
      const failUsage = sandbox.getResourceUsage(failingId);
      expect(passUsage.executionCount).toBe(1);
      expect(failUsage.executionCount).toBe(1);
    });
  });

  // ── Constructor options ─────────────────────────────────────────────

  describe("Constructor options", () => {
    it("default options are applied when none specified", () => {
      const sandbox = new WasmPolicySandbox();
      // Access internal opts for verification
      const opts = (sandbox as any).opts;
      expect(opts.maxMemoryPages).toBe(256);
      expect(opts.executionTimeoutMs).toBe(5000);
      expect(opts.maxModules).toBe(32);
    });

    it("custom options override defaults", () => {
      const sandbox = new WasmPolicySandbox({
        maxMemoryPages: 128,
        executionTimeoutMs: 1000,
        maxModules: 8,
      });
      const opts = (sandbox as any).opts;
      expect(opts.maxMemoryPages).toBe(128);
      expect(opts.executionTimeoutMs).toBe(1000);
      expect(opts.maxModules).toBe(8);
    });
  });
});
