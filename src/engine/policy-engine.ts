import { createHash } from "crypto";
import { v4 as uuidv4 } from "uuid";
import {
  TrustContract,
  PolicyContext,
  PolicyDecision,
  RuleEvaluation,
  EvaluateOptions,
  Obligation,
  DecisionOutcome,
  GovernanceContext,
} from "../types";
import { evaluateRule } from "./evaluator";
import type { StateStore } from "./state-store";

export type PolicyHook = (decision: PolicyDecision) => void | Promise<void>;

export interface PolicyEngineOptions {
  /** Called after every decision. Use for logging, metrics, audit sinks. */
  onDecision?: PolicyHook;
  /** Called when a decision blocks an action. */
  onBlock?: PolicyHook;
  /** Called when a decision produces warnings. */
  onWarn?: PolicyHook;
  /** Called when a decision produces log-level violations. */
  onLog?: PolicyHook;
  /** State store for rate limiting conditions. */
  stateStore?: StateStore;
}

/**
 * The runtime policy engine. Load one or more trust contracts,
 * then call `evaluate()` on every AI action to get a PolicyDecision.
 */
export class PolicyEngine {
  private contracts: TrustContract[] = [];
  private hooks: PolicyEngineOptions;
  private stateStore?: StateStore;

  constructor(opts: PolicyEngineOptions = {}) {
    this.hooks = opts;
    this.stateStore = opts.stateStore;
  }

  /** Register a trust contract with the engine. */
  loadContract(contract: TrustContract): void {
    this.contracts.push(contract);
  }

  /** Remove all loaded contracts. */
  clearContracts(): void {
    this.contracts = [];
  }

  /** Return currently loaded contracts. */
  getContracts(): ReadonlyArray<TrustContract> {
    return this.contracts;
  }

  /** Set the state store for rate limiting. */
  setStateStore(store: StateStore): void {
    this.stateStore = store;
  }

  /**
   * Evaluate a runtime context against all loaded contracts.
   * Returns a single merged PolicyDecision.
   */
  async evaluate(ctx: PolicyContext, opts?: EvaluateOptions): Promise<PolicyDecision> {
    const allEvaluations: RuleEvaluation[] = [];

    for (const contract of this.contracts) {
      let rules = contract.rules;

      // Tag filtering
      if (opts?.includeTags?.length) {
        rules = rules.filter((r) => r.tags?.some((t) => opts.includeTags!.includes(t)));
      }
      if (opts?.excludeTags?.length) {
        rules = rules.filter((r) => !r.tags?.some((t) => opts.excludeTags!.includes(t)));
      }

      for (const rule of rules) {
        const evaluation = await evaluateRule(rule, ctx, { stateStore: this.stateStore });

        // Attach obligations for modify-severity failures
        if (!evaluation.passed && rule.on_violation === "modify" && rule.obligations) {
          evaluation.obligations = rule.obligations.map((o) => ({
            obligation_id: o.obligation_id,
            type: o.type,
            params: o.params,
            source_rule_id: rule.id,
          }));
        }

        // Attach contract version
        evaluation.contract_version = contract.metadata.version;

        allEvaluations.push(evaluation);
      }
    }

    const warnings = allEvaluations.filter((e) => !e.passed && e.severity === "warn");
    const blocks = allEvaluations.filter((e) => !e.passed && e.severity === "block");
    const logs = allEvaluations.filter((e) => !e.passed && e.severity === "log");
    const modifications = allEvaluations.filter((e) => !e.passed && e.severity === "modify");

    // Collect all obligations from modify evaluations
    const obligations: Obligation[] = modifications.flatMap((m) => m.obligations ?? []);

    // Compute outcome: block overrides modify
    let outcome: DecisionOutcome = "permit";
    if (blocks.length > 0) {
      outcome = "deny";
    } else if (modifications.length > 0) {
      outcome = "modify";
    }

    // Compute governance context
    let governance_context: GovernanceContext | undefined;
    if (this.contracts.length > 0) {
      const contract = this.contracts[0];
      const allRules = this.contracts.flatMap((c) => c.rules);
      const rulesPayload = JSON.stringify(allRules);
      const policy_sha256 = createHash("sha256").update(rulesPayload).digest("hex");
      governance_context = {
        contract_id: `${contract.metadata.name}@${contract.metadata.version}`,
        policy_sha256,
      };
    }

    const decision: PolicyDecision = {
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
      governance_context,
    };

    // Fire hooks
    if (this.hooks.onDecision) await this.hooks.onDecision(decision);
    if (blocks.length > 0 && this.hooks.onBlock) await this.hooks.onBlock(decision);
    if (warnings.length > 0 && this.hooks.onWarn) await this.hooks.onWarn(decision);
    if (logs.length > 0 && this.hooks.onLog) await this.hooks.onLog(decision);

    return decision;
  }

  /**
   * Convenience: evaluate and throw if blocked.
   */
  async enforce(ctx: PolicyContext, opts?: EvaluateOptions): Promise<PolicyDecision> {
    const decision = await this.evaluate(ctx, opts);
    if (!decision.allowed) {
      const reasons = decision.blocks.map((b) => `[${b.rule_id}] ${b.rule_description}`).join("; ");
      const err = new PolicyViolationError(`Action "${ctx.action}" blocked: ${reasons}`, decision);
      throw err;
    }
    return decision;
  }
}

export class PolicyViolationError extends Error {
  constructor(
    message: string,
    public readonly decision: PolicyDecision,
  ) {
    super(message);
    this.name = "PolicyViolationError";
  }
}
