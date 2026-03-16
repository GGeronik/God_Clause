import { describe, it, expect } from "vitest";
import { SandboxedEvaluator } from "../src/sandbox/vm-sandbox";
import { PolicyContext, PolicyRule } from "../src/types";

function makeCtx(overrides?: Partial<PolicyContext>): PolicyContext {
  return {
    action: "generate",
    input: { safe: true, score: 85, label: "hello" },
    caller: { user_id: "u1", session_id: "s1", roles: ["admin"] },
    ...overrides,
  };
}

describe("SandboxedEvaluator", () => {
  // ── Constructor ──────────────────────────────────────────────────
  describe("constructor", () => {
    it("applies default options", () => {
      const ev = new SandboxedEvaluator();
      // Verify it works with defaults (timeout=1000, no extra globals, no codegen)
      const result = ev.evaluate("return true;", makeCtx());
      expect(result.passed).toBe(true);
    });

    it("accepts custom timeout override", () => {
      const ev = new SandboxedEvaluator({ timeoutMs: 50 });
      // A tight timeout should still allow simple expressions
      const result = ev.evaluate("return true;", makeCtx());
      expect(result.passed).toBe(true);
    });
  });

  // ── Basic expression evaluation ──────────────────────────────────
  describe("basic expression evaluation", () => {
    const ev = new SandboxedEvaluator();

    it("returns passed:true for a passing boolean expression", () => {
      const result = ev.evaluate("return ctx.input.safe === true;", makeCtx());
      expect(result.passed).toBe(true);
      expect(result.violations).toHaveLength(0);
    });

    it("returns passed:false for a failing boolean expression", () => {
      const result = ev.evaluate("return ctx.input.safe === false;", makeCtx());
      expect(result.passed).toBe(false);
      expect(result.violations).toHaveLength(1);
    });

    it("handles numeric comparisons", () => {
      const result = ev.evaluate("return ctx.input.score > 80;", makeCtx());
      expect(result.passed).toBe(true);

      const result2 = ev.evaluate("return ctx.input.score < 50;", makeCtx());
      expect(result2.passed).toBe(false);
    });

    it("handles string operations", () => {
      const result = ev.evaluate(
        'return ctx.input.label === "hello";',
        makeCtx(),
      );
      expect(result.passed).toBe(true);
    });
  });

  // ── Timeout enforcement ──────────────────────────────────────────
  describe("timeout enforcement", () => {
    it("catches infinite loops and returns passed:false with error", () => {
      const ev = new SandboxedEvaluator({ timeoutMs: 50 });
      const result = ev.evaluate("while(true){}", makeCtx());
      expect(result.passed).toBe(false);
      expect(result.violations).toHaveLength(1);
      expect(result.violations[0].field).toBe("(sandbox_error)");
    });

    it("allows finite computation within timeout", () => {
      const ev = new SandboxedEvaluator({ timeoutMs: 1000 });
      const result = ev.evaluate(
        "let s = 0; for (let i = 0; i < 1000; i++) s += i; return s > 0;",
        makeCtx(),
      );
      expect(result.passed).toBe(true);
    });
  });

  // ── Global isolation ─────────────────────────────────────────────
  describe("global isolation", () => {
    const ev = new SandboxedEvaluator();

    it("process is not accessible", () => {
      const result = ev.evaluate(
        'return typeof process === "undefined";',
        makeCtx(),
      );
      expect(result.passed).toBe(true);
    });

    it("require is not accessible", () => {
      const result = ev.evaluate(
        'return typeof require === "undefined";',
        makeCtx(),
      );
      expect(result.passed).toBe(true);
    });

    it("fs module is not accessible", () => {
      // Attempting to use require or any fs reference should fail
      const result = ev.evaluate(
        'return typeof fs === "undefined";',
        makeCtx(),
      );
      expect(result.passed).toBe(true);
    });

    it("globalThis is restricted (no process, require, etc.)", () => {
      // In the sandbox, globalThis exists but doesn't have dangerous properties
      const result = ev.evaluate(
        'return typeof globalThis.process === "undefined";',
        makeCtx(),
      );
      expect(result.passed).toBe(true);
    });
  });

  // ── Context freezing ─────────────────────────────────────────────
  describe("context freezing", () => {
    const ev = new SandboxedEvaluator();

    it("context is deeply frozen (mutation attempt caught or silently fails)", () => {
      // In non-strict mode, assignment to frozen object silently fails
      // The expression tries to mutate then checks if the original value remains
      const result = ev.evaluate(
        "try { ctx.input.safe = false; } catch(e) { return true; } return ctx.input.safe === true;",
        makeCtx(),
      );
      expect(result.passed).toBe(true);
    });

    it("original context is not modified after evaluation", () => {
      const ctx = makeCtx();
      ev.evaluate(
        "try { ctx.input.safe = false; } catch(e) {}",
        ctx,
      );
      // The original context must be untouched (structuredClone was used)
      expect(ctx.input.safe).toBe(true);
    });
  });

  // ── Code generation restrictions ─────────────────────────────────
  describe("code generation restrictions", () => {
    it("eval() is blocked when codeGeneration.strings is false", () => {
      const ev = new SandboxedEvaluator({
        codeGeneration: { strings: false, wasm: false },
      });
      const result = ev.evaluate(
        'return eval("1 + 1") === 2;',
        makeCtx(),
      );
      expect(result.passed).toBe(false);
      expect(result.violations[0].field).toBe("(sandbox_error)");
    });

    it("Function constructor is blocked when codeGeneration.strings is false", () => {
      const ev = new SandboxedEvaluator({
        codeGeneration: { strings: false, wasm: false },
      });
      const result = ev.evaluate(
        'var f = new Function("return 42"); return f() === 42;',
        makeCtx(),
      );
      expect(result.passed).toBe(false);
      expect(result.violations[0].field).toBe("(sandbox_error)");
    });
  });

  // ── Rule evaluation ──────────────────────────────────────────────
  describe("evaluateRule", () => {
    const ev = new SandboxedEvaluator();

    const passingRule: PolicyRule = {
      id: "r1",
      description: "Input must be safe",
      action: "generate",
      conditions: [{ field: "input.safe", operator: "equals", value: true }],
      on_violation: "block",
    };

    const failingRule: PolicyRule = {
      id: "r2",
      description: "Score must be low",
      action: "generate",
      conditions: [
        { field: "input.score", operator: "less_than", value: 50 },
      ],
      on_violation: "warn",
    };

    const nonMatchingRule: PolicyRule = {
      id: "r3",
      description: "Only for classify",
      action: "classify",
      conditions: [{ field: "input.safe", operator: "equals", value: false }],
      on_violation: "block",
    };

    it("passes for matching conditions", async () => {
      const result = await ev.evaluateRule(passingRule, makeCtx());
      expect(result.passed).toBe(true);
      expect(result.rule_id).toBe("r1");
      expect(result.violated_conditions).toHaveLength(0);
    });

    it("fails for violated conditions", async () => {
      const result = await ev.evaluateRule(failingRule, makeCtx());
      expect(result.passed).toBe(false);
      expect(result.rule_id).toBe("r2");
      expect(result.violated_conditions.length).toBeGreaterThan(0);
    });

    it("auto-passes when action does not match", async () => {
      const result = await ev.evaluateRule(nonMatchingRule, makeCtx());
      expect(result.passed).toBe(true);
      expect(result.violated_conditions).toHaveLength(0);
    });

    it("returns proper RuleEvaluation shape", async () => {
      const result = await ev.evaluateRule(passingRule, makeCtx());
      expect(result).toHaveProperty("rule_id");
      expect(result).toHaveProperty("rule_description");
      expect(result).toHaveProperty("passed");
      expect(result).toHaveProperty("severity");
      expect(result).toHaveProperty("violated_conditions");
      expect(result).toHaveProperty("timestamp");
      expect(typeof result.timestamp).toBe("string");
    });
  });

  // ── Custom context / createRestrictedContext ──────────────────────
  describe("createRestrictedContext", () => {
    const ev = new SandboxedEvaluator();

    it("includes safe builtins (JSON, Math, etc.)", () => {
      const result = ev.evaluate(
        "return typeof JSON.stringify === 'function' && typeof Math.max === 'function';",
        makeCtx(),
      );
      expect(result.passed).toBe(true);
    });

    it("includes extras passed to createRestrictedContext", () => {
      // We test indirectly: evaluate uses createRestrictedContext with ctx as extra
      const result = ev.evaluate(
        "return ctx.action === 'generate';",
        makeCtx(),
      );
      expect(result.passed).toBe(true);
    });

    it("allowedGlobals option works", () => {
      const ev2 = new SandboxedEvaluator({
        allowedGlobals: { MY_CONST: 42 },
      });
      const result = ev2.evaluate("return MY_CONST === 42;", makeCtx());
      expect(result.passed).toBe(true);
    });
  });
});
