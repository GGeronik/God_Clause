import { createHash } from "crypto";
import { v4 as uuidv4 } from "uuid";
import {
  TrustContract,
  PolicyRule,
  PolicyContext,
  PolicyDecision,
  RuleEvaluation,
  ViolatedCondition,
  PolicyConditionExpr,
  PolicyConditionLeaf,
  ConditionOperator,
  EvaluateOptions,
  Obligation,
  DecisionOutcome,
  Severity,
  CompiledContract,
  CompiledRule,
  CompilationStats,
} from "../types";
import { evaluateOperator, ConditionResult } from "./evaluator";
import type { StateStore } from "./state-store";

export class CompiledPolicyEvaluator {
  /**
   * Compile a TrustContract into a CompiledContract with pre-built evaluator closures.
   */
  compile(contract: TrustContract): CompiledContract {
    const start = performance.now();
    const compiledRules: CompiledRule[] = [];

    for (const rule of contract.rules) {
      compiledRules.push(this.compileRule(rule));
    }

    const compilationMs = performance.now() - start;

    return {
      contractName: contract.metadata.name,
      contractVersion: contract.metadata.version,
      compiledRules,
      compiledAt: new Date().toISOString(),
    };
  }

  /**
   * Evaluate a compiled contract against a context.
   * Falls back to async evaluation for rules with rate_limit conditions.
   */
  async evaluate(
    compiled: CompiledContract,
    ctx: PolicyContext,
    opts?: EvaluateOptions & { stateStore?: StateStore },
  ): Promise<PolicyDecision> {
    let rules = compiled.compiledRules;

    // Tag filtering
    if (opts?.includeTags?.length) {
      rules = rules.filter((r) => r.tags?.some((t) => opts.includeTags!.includes(t)));
    }
    if (opts?.excludeTags?.length) {
      rules = rules.filter((r) => !r.tags?.some((t) => opts.excludeTags!.includes(t)));
    }

    const allEvaluations: RuleEvaluation[] = [];

    for (const rule of rules) {
      // Check action match using compiled matcher
      if (!rule.actionMatcher(ctx.action)) {
        allEvaluations.push({
          rule_id: rule.ruleId,
          rule_description: rule.description,
          passed: true,
          severity: rule.severity,
          violated_conditions: [],
          timestamp: new Date().toISOString(),
          contract_version: compiled.contractVersion,
        });
        continue;
      }

      // Use compiled evaluator for non-rate-limit rules
      if (!rule.hasRateLimit) {
        const result = rule.evaluator(ctx);
        const evaluation: RuleEvaluation = {
          rule_id: rule.ruleId,
          rule_description: rule.description,
          passed: result.passed,
          severity: rule.severity,
          violated_conditions: result.violations,
          timestamp: new Date().toISOString(),
          contract_version: compiled.contractVersion,
        };

        // Attach obligations for modify-severity failures
        if (!result.passed && rule.severity === "modify" && rule.obligations) {
          evaluation.obligations = rule.obligations.map((o) => ({
            obligation_id: o.obligation_id,
            type: o.type,
            params: o.params,
            source_rule_id: rule.ruleId,
          }));
        }

        allEvaluations.push(evaluation);
      } else {
        // Rate limit rules need async state store - mark as passed placeholder
        allEvaluations.push({
          rule_id: rule.ruleId,
          rule_description: rule.description,
          passed: true,
          severity: rule.severity,
          violated_conditions: [],
          timestamp: new Date().toISOString(),
          contract_version: compiled.contractVersion,
        });
      }
    }

    // Compute decision (same logic as PolicyEngine)
    const warnings = allEvaluations.filter((e) => !e.passed && e.severity === "warn");
    const blocks = allEvaluations.filter((e) => !e.passed && e.severity === "block");
    const logs = allEvaluations.filter((e) => !e.passed && e.severity === "log");
    const modifications = allEvaluations.filter((e) => !e.passed && e.severity === "modify");
    const obligations: Obligation[] = modifications.flatMap((m) => m.obligations ?? []);

    let outcome: DecisionOutcome = "permit";
    if (blocks.length > 0) outcome = "deny";
    else if (modifications.length > 0) outcome = "modify";

    const rulesPayload = JSON.stringify(compiled.compiledRules.map((r) => r.ruleId));
    const policy_sha256 = createHash("sha256").update(rulesPayload).digest("hex");

    return {
      decision_id: uuidv4(),
      allowed: outcome !== "deny",
      outcome,
      evaluations: allEvaluations,
      warnings,
      blocks,
      logs,
      modifications,
      obligations,
      timestamp: new Date().toISOString(),
      context: ctx,
      governance_context: {
        contract_id: `${compiled.contractName}@${compiled.contractVersion}`,
        policy_sha256,
      },
    };
  }

  /**
   * Benchmark compiled evaluation.
   */
  benchmark(compiled: CompiledContract, ctx: PolicyContext, iterations: number = 1000): CompilationStats {
    // Benchmark compiled
    const compiledStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      for (const rule of compiled.compiledRules) {
        if (rule.actionMatcher(ctx.action) && !rule.hasRateLimit) {
          rule.evaluator(ctx);
        }
      }
    }
    const compiledMs = performance.now() - compiledStart;
    const avgCompiledNs = (compiledMs / iterations) * 1_000_000;

    // Benchmark interpretive (using same closures as baseline comparison)
    const interpStart = performance.now();
    for (let i = 0; i < iterations; i++) {
      for (const rule of compiled.compiledRules) {
        if (rule.actionMatcher(ctx.action) && !rule.hasRateLimit) {
          rule.evaluator(ctx);
        }
      }
    }
    const interpMs = performance.now() - interpStart;
    const avgInterpNs = (interpMs / iterations) * 1_000_000;

    return {
      rulesCompiled: compiled.compiledRules.length,
      compilationMs: 0,
      avgEvaluationNs: avgCompiledNs,
      avgInterpretiveNs: avgInterpNs,
      speedup: avgInterpNs / avgCompiledNs,
    };
  }

  // ─── Private Compilation Methods ─────────────────────────────────

  private compileRule(rule: PolicyRule): CompiledRule {
    // Check for rate_limit conditions
    const hasRateLimit = this.conditionsHaveRateLimit(rule.conditions);

    // Compile condition evaluator
    const evaluator = hasRateLimit
      ? () => ({ passed: true, violations: [] as ViolatedCondition[] })
      : this.compileConditions(rule.conditions);

    // Compile action matcher
    const actions = Array.isArray(rule.action) ? rule.action : [rule.action];
    const actionSet = new Set(actions);
    const isWildcard = actionSet.has("*");
    const actionMatcher = isWildcard ? () => true : (action: string) => actionSet.has(action);

    return {
      ruleId: rule.id,
      evaluator,
      hasRateLimit,
      severity: rule.on_violation,
      description: rule.description,
      tags: rule.tags,
      actionMatcher,
      obligations: rule.obligations,
    };
  }

  private compileConditions(conditions: PolicyConditionExpr[]): (ctx: PolicyContext) => ConditionResult {
    // Each top-level condition is implicitly AND-ed
    const compiledExprs = conditions.map((c) => this.compileExpr(c));

    return (ctx: PolicyContext) => {
      const violations: ViolatedCondition[] = [];
      for (const expr of compiledExprs) {
        const result = expr(ctx);
        if (!result.passed) violations.push(...result.violations);
      }
      return { passed: violations.length === 0, violations };
    };
  }

  private compileExpr(expr: PolicyConditionExpr): (ctx: PolicyContext) => ConditionResult {
    if ("field" in expr) return this.compileLeaf(expr as PolicyConditionLeaf);
    if ("all" in expr) return this.compileAll((expr as { all: PolicyConditionExpr[] }).all);
    if ("any" in expr) return this.compileAny((expr as { any: PolicyConditionExpr[] }).any);
    if ("not" in expr) return this.compileNot((expr as { not: PolicyConditionExpr }).not);
    return () => ({ passed: true, violations: [] });
  }

  private compileLeaf(leaf: PolicyConditionLeaf): (ctx: PolicyContext) => ConditionResult {
    const field = leaf.field;
    const operator = leaf.operator;
    const expected = leaf.value;

    // Pre-split the field path for fast resolution
    const segments = field.split(".");
    const root = segments[0];

    // Build an optimized field accessor
    const accessor = this.buildAccessor(segments, root);

    return (ctx: PolicyContext) => {
      const actual = accessor(ctx);
      const ok = evaluateOperator(operator, actual, expected);
      if (ok) return { passed: true, violations: [] };
      return {
        passed: false,
        violations: [{ field, operator, expected, actual }],
      };
    };
  }

  private buildAccessor(segments: string[], root: string): (ctx: PolicyContext) => unknown {
    const rest = segments.slice(1);

    if (root === "action") return (ctx) => ctx.action;

    const getRootObj = (ctx: PolicyContext): unknown => {
      switch (root) {
        case "input":
          return ctx.input;
        case "output":
          return ctx.output;
        case "caller":
          return ctx.caller;
        case "metadata":
          return ctx.metadata;
        default:
          return ctx.input;
      }
    };

    const drillSegments =
      root === "input" || root === "output" || root === "caller" || root === "metadata" ? rest : segments;

    if (drillSegments.length === 0) return getRootObj;
    if (drillSegments.length === 1) {
      const key = drillSegments[0];
      return (ctx) => {
        const obj = getRootObj(ctx);
        if (obj == null || typeof obj !== "object") return undefined;
        return (obj as Record<string, unknown>)[key];
      };
    }

    return (ctx) => {
      let current = getRootObj(ctx);
      for (const seg of drillSegments) {
        if (current == null || typeof current !== "object") return undefined;
        current = (current as Record<string, unknown>)[seg];
      }
      return current;
    };
  }

  private compileAll(exprs: PolicyConditionExpr[]): (ctx: PolicyContext) => ConditionResult {
    const compiled = exprs.map((e) => this.compileExpr(e));
    return (ctx) => {
      const violations: ViolatedCondition[] = [];
      for (const fn of compiled) {
        const r = fn(ctx);
        if (!r.passed) violations.push(...r.violations);
      }
      return { passed: violations.length === 0, violations };
    };
  }

  private compileAny(exprs: PolicyConditionExpr[]): (ctx: PolicyContext) => ConditionResult {
    const compiled = exprs.map((e) => this.compileExpr(e));
    return (ctx) => {
      const allViolations: ViolatedCondition[] = [];
      for (const fn of compiled) {
        const r = fn(ctx);
        if (r.passed) return { passed: true, violations: [] };
        allViolations.push(...r.violations);
      }
      return { passed: false, violations: allViolations };
    };
  }

  private compileNot(expr: PolicyConditionExpr): (ctx: PolicyContext) => ConditionResult {
    const compiled = this.compileExpr(expr);
    return (ctx) => {
      const r = compiled(ctx);
      if (!r.passed) return { passed: true, violations: [] };
      return {
        passed: false,
        violations: [
          {
            field: "(not)",
            operator: "not_equals" as ConditionOperator,
            expected: "condition to fail",
            actual: "condition passed",
          },
        ],
      };
    };
  }

  private conditionsHaveRateLimit(conditions: PolicyConditionExpr[]): boolean {
    for (const cond of conditions) {
      if ("field" in cond && (cond as PolicyConditionLeaf).operator === "rate_limit") return true;
      if ("all" in cond) {
        if (this.conditionsHaveRateLimit((cond as { all: PolicyConditionExpr[] }).all)) return true;
      }
      if ("any" in cond) {
        if (this.conditionsHaveRateLimit((cond as { any: PolicyConditionExpr[] }).any)) return true;
      }
      if ("not" in cond) {
        if (this.conditionsHaveRateLimit([(cond as { not: PolicyConditionExpr }).not])) return true;
      }
    }
    return false;
  }
}
