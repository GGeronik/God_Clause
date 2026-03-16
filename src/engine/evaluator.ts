import {
  PolicyRule,
  PolicyConditionExpr,
  PolicyConditionLeaf,
  PolicyContext,
  RuleEvaluation,
  ViolatedCondition,
  ConditionOperator,
  ActionVerb,
  RateLimitValue,
} from "../types";
import type { StateStore } from "./state-store";
import { parseISO8601Duration } from "./state-store";

/** Context passed to async evaluator functions. */
export interface EvaluatorContext {
  stateStore?: StateStore;
}

/**
 * Resolve a dot-notation field path against a context object.
 * Checks input, output, caller, then metadata in that order.
 */
export function resolveField(ctx: PolicyContext, field: string): unknown {
  const segments = field.split(".");
  const root = segments[0];
  let target: unknown;

  if (root === "input") {
    target = ctx.input;
  } else if (root === "output") {
    target = ctx.output;
  } else if (root === "caller") {
    target = ctx.caller;
  } else if (root === "metadata") {
    target = ctx.metadata;
  } else if (root === "action") {
    return ctx.action;
  } else {
    // Try input first, then metadata
    target = ctx.input;
    return drillDown(target, segments);
  }

  return drillDown(target, segments.slice(1));
}

function drillDown(obj: unknown, segments: string[]): unknown {
  let current = obj;
  for (const seg of segments) {
    if (current == null || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[seg];
  }
  return current;
}

export function evaluateOperator(
  operator: ConditionOperator,
  actual: unknown,
  expected: unknown,
): boolean {
  switch (operator) {
    case "equals":
      return actual === expected;
    case "not_equals":
      return actual !== expected;
    case "contains":
      if (typeof actual === "string" && typeof expected === "string")
        return actual.includes(expected);
      if (Array.isArray(actual)) return actual.includes(expected);
      return false;
    case "not_contains":
      if (typeof actual === "string" && typeof expected === "string")
        return !actual.includes(expected);
      if (Array.isArray(actual)) return !actual.includes(expected);
      return true;
    case "greater_than":
      return typeof actual === "number" && typeof expected === "number" && actual > expected;
    case "less_than":
      return typeof actual === "number" && typeof expected === "number" && actual < expected;
    case "in":
      return Array.isArray(expected) && expected.includes(actual);
    case "not_in":
      return Array.isArray(expected) && !expected.includes(actual);
    case "matches":
      if (typeof actual === "string" && typeof expected === "string") {
        return new RegExp(expected).test(actual);
      }
      return false;
    case "exists":
      return actual !== undefined && actual !== null;
    case "not_exists":
      return actual === undefined || actual === null;
    case "rate_limit":
      // Handled asynchronously in evaluateConditionExprAsync
      return true;
    default:
      return false;
  }
}

export function actionMatches(
  ruleAction: ActionVerb | ActionVerb[],
  contextAction: ActionVerb,
): boolean {
  const actions = Array.isArray(ruleAction) ? ruleAction : [ruleAction];
  return actions.includes("*") || actions.includes(contextAction);
}

// ─── Type Guards ─────────────────────────────────────────────────────

function isLeaf(expr: PolicyConditionExpr): expr is PolicyConditionLeaf {
  return "field" in expr;
}

function isAll(expr: PolicyConditionExpr): expr is { all: PolicyConditionExpr[] } {
  return "all" in expr;
}

function isAny(expr: PolicyConditionExpr): expr is { any: PolicyConditionExpr[] } {
  return "any" in expr;
}

function isNot(expr: PolicyConditionExpr): expr is { not: PolicyConditionExpr } {
  return "not" in expr;
}

// ─── Recursive Condition Evaluator ───────────────────────────────────

export interface ConditionResult {
  passed: boolean;
  violations: ViolatedCondition[];
}

/**
 * Recursively evaluate a condition expression (leaf, all, any, not).
 * Synchronous version — throws on rate_limit conditions.
 */
export function evaluateConditionExpr(
  expr: PolicyConditionExpr,
  ctx: PolicyContext,
): ConditionResult {
  if (isLeaf(expr)) {
    if (expr.operator === "rate_limit") {
      throw new Error("rate_limit conditions require async evaluation. Use evaluateRule() instead.");
    }
    const actual = resolveField(ctx, expr.field);
    const ok = evaluateOperator(expr.operator, actual, expr.value);
    if (ok) {
      return { passed: true, violations: [] };
    }
    return {
      passed: false,
      violations: [{
        field: expr.field,
        operator: expr.operator,
        expected: expr.value,
        actual,
      }],
    };
  }

  if (isAll(expr)) {
    const allViolations: ViolatedCondition[] = [];
    for (const child of expr.all) {
      const result = evaluateConditionExpr(child, ctx);
      if (!result.passed) {
        allViolations.push(...result.violations);
      }
    }
    return {
      passed: allViolations.length === 0,
      violations: allViolations,
    };
  }

  if (isAny(expr)) {
    const branchViolations: ViolatedCondition[] = [];
    for (const child of expr.any) {
      const result = evaluateConditionExpr(child, ctx);
      if (result.passed) {
        return { passed: true, violations: [] };
      }
      branchViolations.push(...result.violations);
    }
    // None passed — report all branch violations
    return { passed: false, violations: branchViolations };
  }

  if (isNot(expr)) {
    const result = evaluateConditionExpr(expr.not, ctx);
    if (!result.passed) {
      // Child failed → NOT succeeds
      return { passed: true, violations: [] };
    }
    // Child passed → NOT fails, synthesize a violation
    return {
      passed: false,
      violations: [{
        field: "(not)",
        operator: "not_equals" as ConditionOperator,
        expected: "condition to fail",
        actual: "condition passed",
      }],
    };
  }

  return { passed: true, violations: [] };
}

/**
 * Async recursive condition evaluator — handles rate_limit and all other operators.
 */
async function evaluateConditionExprAsync(
  expr: PolicyConditionExpr,
  ctx: PolicyContext,
  evalCtx: EvaluatorContext,
): Promise<ConditionResult> {
  if (isLeaf(expr)) {
    if (expr.operator === "rate_limit") {
      return evaluateRateLimit(expr, ctx, evalCtx);
    }
    const actual = resolveField(ctx, expr.field);
    const ok = evaluateOperator(expr.operator, actual, expr.value);
    if (ok) {
      return { passed: true, violations: [] };
    }
    return {
      passed: false,
      violations: [{
        field: expr.field,
        operator: expr.operator,
        expected: expr.value,
        actual,
      }],
    };
  }

  if (isAll(expr)) {
    const allViolations: ViolatedCondition[] = [];
    for (const child of expr.all) {
      const result = await evaluateConditionExprAsync(child, ctx, evalCtx);
      if (!result.passed) {
        allViolations.push(...result.violations);
      }
    }
    return {
      passed: allViolations.length === 0,
      violations: allViolations,
    };
  }

  if (isAny(expr)) {
    const branchViolations: ViolatedCondition[] = [];
    for (const child of expr.any) {
      const result = await evaluateConditionExprAsync(child, ctx, evalCtx);
      if (result.passed) {
        return { passed: true, violations: [] };
      }
      branchViolations.push(...result.violations);
    }
    return { passed: false, violations: branchViolations };
  }

  if (isNot(expr)) {
    const result = await evaluateConditionExprAsync(expr.not, ctx, evalCtx);
    if (!result.passed) {
      return { passed: true, violations: [] };
    }
    return {
      passed: false,
      violations: [{
        field: "(not)",
        operator: "not_equals" as ConditionOperator,
        expected: "condition to fail",
        actual: "condition passed",
      }],
    };
  }

  return { passed: true, violations: [] };
}

/**
 * Evaluate a rate_limit condition using the state store.
 */
async function evaluateRateLimit(
  expr: PolicyConditionLeaf,
  ctx: PolicyContext,
  evalCtx: EvaluatorContext,
): Promise<ConditionResult> {
  if (!evalCtx.stateStore) {
    throw new Error("rate_limit conditions require a StateStore. Pass one via GodClause options or PolicyEngine.setStateStore().");
  }

  const value = expr.value as RateLimitValue;
  const fieldValue = resolveField(ctx, expr.field);
  const key = `rate:${expr.field}:${String(fieldValue)}`;
  const windowMs = parseISO8601Duration(value.window);
  const count = await evalCtx.stateStore.recordAndCount(key, windowMs);

  if (count <= value.max) {
    return { passed: true, violations: [] };
  }

  return {
    passed: false,
    violations: [{
      field: expr.field,
      operator: "rate_limit",
      expected: value,
      actual: count,
    }],
  };
}

/**
 * Evaluate a single rule against a runtime context.
 * Now async to support rate_limit conditions.
 */
export async function evaluateRule(
  rule: PolicyRule,
  ctx: PolicyContext,
  evalCtx: EvaluatorContext = {},
): Promise<RuleEvaluation> {
  const timestamp = new Date().toISOString();

  // If the rule doesn't apply to this action, it passes automatically.
  if (!actionMatches(rule.action, ctx.action)) {
    return {
      rule_id: rule.id,
      rule_description: rule.description,
      passed: true,
      severity: rule.on_violation,
      violated_conditions: [],
      timestamp,
    };
  }

  const violations: ViolatedCondition[] = [];

  // Each top-level condition in the array is implicitly AND-ed
  for (const cond of rule.conditions) {
    const result = await evaluateConditionExprAsync(cond, ctx, evalCtx);
    if (!result.passed) {
      violations.push(...result.violations);
    }
  }

  return {
    rule_id: rule.id,
    rule_description: rule.description,
    passed: violations.length === 0,
    severity: rule.on_violation,
    violated_conditions: violations,
    timestamp,
  };
}
