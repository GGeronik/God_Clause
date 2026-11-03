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
import { MCPRouter } from "./mcp-router";
import { MemoryStateStore, type StateStore } from "./state-store";

/** Receives the decision and the contracts it was evaluated against (a snapshot; later reloads do not change it). */
export type PolicyHook = (decision: PolicyDecision, contracts: ReadonlyArray<TrustContract>) => void | Promise<void>;

export interface PolicyEngineOptions {
  /** Called after every decision. Use for logging, metrics, audit sinks. */
  onDecision?: PolicyHook;
  /** Called when a decision blocks an action. */
  onBlock?: PolicyHook;
  /** Called when a decision produces warnings. */
  onWarn?: PolicyHook;
  /** Called when a decision produces log-level violations. */
  onLog?: PolicyHook;
  /** State store for rate limiting conditions. Defaults to an in-memory store; pass a shared one for several processes. */
  stateStore?: StateStore;
}

/**
 * The runtime policy engine. Load one or more trust contracts,
 * then call `evaluate()` on every AI action to get a PolicyDecision.
 */
export class PolicyEngine {
  private contracts: TrustContract[] = [];
  private hooks: PolicyEngineOptions;
  private stateStore: StateStore;

  constructor(opts: PolicyEngineOptions = {}) {
    this.hooks = opts;
    this.stateStore = opts.stateStore ?? new MemoryStateStore();
  }

  /** Register a trust contract with the engine; the same name and version replaces the earlier copy. */
  loadContract(contract: TrustContract): void {
    const { name, version } = contract.metadata;
    const i = this.contracts.findIndex((c) => c.metadata.name === name && c.metadata.version === version);
    if (i === -1) this.contracts.push(contract);
    else this.contracts[i] = contract;
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
    // One snapshot for the whole evaluation, so a reload landing mid-way cannot mix two policy sets.
    const contracts = this.contracts;

    if (contracts.length === 0) {
      allEvaluations.push({
        rule_id: "NO-CONTRACT",
        rule_description: "No trust contract is loaded",
        passed: false,
        severity: "block",
        violated_conditions: [],
        timestamp: new Date().toISOString(),
      });
    }

    for (const contract of contracts) {
      let rules = contract.rules;

      // Tag filtering
      if (opts?.includeTags?.length) {
        rules = rules.filter((r) => r.tags?.some((t) => opts.includeTags!.includes(t)));
      }
      if (opts?.excludeTags?.length) {
        rules = rules.filter((r) => !r.tags?.some((t) => opts.excludeTags!.includes(t)));
      }

      for (const rule of rules) {
        let evaluation: RuleEvaluation;
        try {
          evaluation = await evaluateRule(rule, ctx, { stateStore: this.stateStore });
        } catch (err) {
          // A rule that cannot be evaluated fails closed, whatever its on_violation says.
          evaluation = {
            rule_id: rule.id,
            rule_description: rule.description,
            passed: false,
            severity: "block",
            violated_conditions: [],
            timestamp: new Date().toISOString(),
            error: errorText(err),
          };
        }

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

    // A tool invocation (metadata.mcp_tool) is also judged by the contracts' mcp_permissions: first match wins,
    // and with no matching (or no loaded) permission the tool is denied.
    const tool = ctx.metadata?.mcp_tool;
    const permissions = contracts.flatMap((c) => c.mcp_permissions ?? []);
    if (typeof tool === "string") {
      const result = await new MCPRouter(permissions, this.stateStore).authorize(
        { tool_name: tool, arguments: ctx.input ?? {}, session_id: ctx.caller.session_id },
        ctx,
      );
      if (!result.allowed || result.require_human_approval) {
        allEvaluations.push({
          rule_id: "MCP-PERMISSIONS",
          rule_description: result.allowed
            ? `Tool "${tool}" requires human approval`
            : (result.denial_reason ?? `Tool "${tool}" denied`),
          passed: false,
          severity: result.allowed ? "modify" : "block",
          violated_conditions: [],
          timestamp: new Date().toISOString(),
          obligations: result.allowed
            ? [
                {
                  obligation_id: "OBL-MCP-HUMAN-APPROVAL",
                  type: "require_review",
                  params: { tool },
                  source_rule_id: "MCP-PERMISSIONS",
                },
              ]
            : undefined,
        });
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
    if (contracts.length > 0) {
      const contract = contracts[0];
      const allRules = contracts.flatMap((c) => c.rules);
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
    if (this.hooks.onDecision) await this.hooks.onDecision(decision, contracts);
    if (blocks.length > 0 && this.hooks.onBlock) await this.hooks.onBlock(decision, contracts);
    if (warnings.length > 0 && this.hooks.onWarn) await this.hooks.onWarn(decision, contracts);
    if (logs.length > 0 && this.hooks.onLog) await this.hooks.onLog(decision, contracts);

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

function errorText(err: unknown): string {
  try {
    return String(err instanceof Error ? err.message : err);
  } catch {
    return "error could not be converted to text";
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
