import * as vm from "node:vm";
import {
  SandboxOptions,
  PolicyContext,
  PolicyRule,
  RuleEvaluation,
  ViolatedCondition,
  ConditionOperator,
} from "../types";
import { ConditionResult } from "../engine/evaluator";

export class SandboxedEvaluator {
  private opts: Required<SandboxOptions>;

  constructor(opts?: SandboxOptions) {
    this.opts = {
      timeoutMs: opts?.timeoutMs ?? 1000,
      allowedGlobals: opts?.allowedGlobals ?? {},
      codeGeneration: opts?.codeGeneration ?? { strings: false, wasm: false },
    };
  }

  /**
   * Evaluate a JavaScript expression in a restricted VM context.
   * The expression receives `ctx` (frozen PolicyContext) and must return a boolean.
   * Returns a ConditionResult.
   */
  evaluate(code: string, context: PolicyContext): ConditionResult {
    const frozenCtx = deepFreeze(structuredClone(context));
    const sandbox = this.createRestrictedContext({ ctx: frozenCtx });

    const script = new vm.Script(`(function() { ${code} })()`);

    try {
      const result = script.runInContext(sandbox, {
        timeout: this.opts.timeoutMs,
      });

      if (typeof result === "boolean") {
        return result
          ? { passed: true, violations: [] }
          : {
              passed: false,
              violations: [
                {
                  field: "(sandbox)",
                  operator: "equals" as ConditionOperator,
                  expected: true,
                  actual: false,
                },
              ],
            };
      }

      // If result is a ConditionResult-shaped object, return it
      if (result && typeof result === "object" && "passed" in result) {
        return result as ConditionResult;
      }

      return { passed: Boolean(result), violations: [] };
    } catch (err) {
      return {
        passed: false,
        violations: [
          {
            field: "(sandbox_error)",
            operator: "equals" as ConditionOperator,
            expected: "successful execution",
            actual: err instanceof Error ? err.message : String(err),
          },
        ],
      };
    }
  }

  /**
   * Evaluate a PolicyRule against a context using the sandbox.
   * Rules with conditions use sandboxed evaluation via generated JS expressions.
   */
  async evaluateRule(rule: PolicyRule, context: PolicyContext): Promise<RuleEvaluation> {
    // Check action match first
    const actions = Array.isArray(rule.action) ? rule.action : [rule.action];
    const matches = actions.includes("*") || actions.includes(context.action);

    if (!matches) {
      return {
        rule_id: rule.id,
        rule_description: rule.description,
        passed: true,
        severity: rule.on_violation,
        violated_conditions: [],
        timestamp: new Date().toISOString(),
      };
    }

    // Evaluate each condition - use sandbox for all
    const violations: ViolatedCondition[] = [];
    for (const cond of rule.conditions) {
      if ("field" in cond) {
        // Build expression from condition
        const code = `return ctx.${cond.field} ${operatorToJS(cond.operator)} ${JSON.stringify(cond.value)};`;
        const result = this.evaluate(code, context);
        if (!result.passed) violations.push(...result.violations);
      }
    }

    return {
      rule_id: rule.id,
      rule_description: rule.description,
      passed: violations.length === 0,
      severity: rule.on_violation,
      violated_conditions: violations,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Create a restricted VM context with only safe globals.
   */
  createRestrictedContext(extras?: Record<string, unknown>): vm.Context {
    const sandbox: Record<string, unknown> = {
      // Safe built-ins only
      JSON: JSON,
      Math: Math,
      String: String,
      Number: Number,
      Array: Array,
      Object: Object,
      RegExp: RegExp,
      Boolean: Boolean,
      parseInt: parseInt,
      parseFloat: parseFloat,
      isNaN: isNaN,
      isFinite: isFinite,
      Date: { now: () => Date.now() }, // Restricted Date - no constructor
      ...this.opts.allowedGlobals,
      ...extras,
    };

    return vm.createContext(sandbox, {
      codeGeneration: this.opts.codeGeneration,
    });
  }
}

function deepFreeze<T>(obj: T): T {
  if (obj === null || typeof obj !== "object") return obj;
  Object.freeze(obj);
  for (const val of Object.values(obj as Record<string, unknown>)) {
    if (val !== null && typeof val === "object") deepFreeze(val);
  }
  return obj;
}

function operatorToJS(op: string): string {
  switch (op) {
    case "equals":
      return "===";
    case "not_equals":
      return "!==";
    case "greater_than":
      return ">";
    case "less_than":
      return "<";
    default:
      return "===";
  }
}
