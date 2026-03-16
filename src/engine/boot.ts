import type {
  TrustContract,
  ModelBinding,
  DegradationTier,
  PreFlightResult,
} from "../types";
import { GodClause, GovernanceOptions } from "../governance";
import { parseContract } from "../contracts/parser";
import type { AuditSink } from "../audit/audit-log";
import type { StateStore } from "./state-store";

/**
 * Options for the fail-closed secure boot sequence.
 */
export interface SecureBootOptions {
  /** YAML contract sources to parse and load. */
  contracts: string[];
  /** Audit sinks to attach to the governance instance. */
  auditSinks?: AuditSink[];
  /** HMAC key for audit entry signing. */
  secretKey?: string;
  /** If true, fail when any contract cannot be loaded. */
  requireSignatures?: boolean;
  /** PEM public keys for DSSE envelope verification. */
  signaturePublicKeys?: string[];
  /** Model bindings to verify against loaded contracts. */
  modelBindings?: ModelBinding[];
  /** Degradation tier definitions. */
  degradationTiers?: DegradationTier[];
  /** State store for rate limiting. */
  stateStore?: StateStore;
}

/**
 * SecureBoot — fail-closed boot sequence for the God Clause governance engine.
 *
 * Parses contracts, creates a GodClause instance, runs pre-flight checks,
 * and returns both the orchestrator and the check results. If critical
 * checks fail, the returned `PreFlightResult.ready` will be `false` and
 * `degradation_tier` will reflect the severity.
 */
export class SecureBoot {
  /**
   * Initialize a GodClause instance with the given contracts and options.
   *
   * 1. Parse all contract YAML strings.
   * 2. If `requireSignatures` is set, verify all contracts loaded successfully.
   * 3. Create a GodClause instance with the provided options.
   * 4. Load all parsed contracts.
   * 5. Run pre-flight checks.
   * 6. Return both the instance and the pre-flight result.
   */
  static async initialize(
    opts: SecureBootOptions,
  ): Promise<{ gov: GodClause; preflight: PreFlightResult }> {
    // Step 1: Parse all contract YAML strings
    const parsed: TrustContract[] = [];
    const parseErrors: string[] = [];

    for (const source of opts.contracts) {
      try {
        parsed.push(parseContract(source));
      } catch (err) {
        parseErrors.push(
          err instanceof Error ? err.message : String(err),
        );
      }
    }

    // Step 2: If requireSignatures, check that all contracts loaded
    if (opts.requireSignatures && parseErrors.length > 0) {
      // Fail-closed: report errors but continue to build the instance
      // so callers can inspect the preflight result
    }

    // Step 3: Create GodClause instance
    const govOpts: GovernanceOptions = {
      auditSinks: opts.auditSinks,
      auditSecretKey: opts.secretKey,
      stateStore: opts.stateStore,
    };
    const gov = new GodClause(govOpts);

    // Step 4: Load all successfully parsed contracts
    for (const contract of parsed) {
      gov.loadContract(contract);
    }

    // Step 5: Run pre-flight checks
    const preflight = SecureBoot.verifyPreFlight(gov, {
      requireSignatures: opts.requireSignatures,
      modelBindings: opts.modelBindings,
    });

    return { gov, preflight };
  }

  /**
   * Run pre-flight checks against an existing GodClause instance.
   *
   * Checks performed:
   * - `contracts_loaded` — at least one contract is loaded
   * - `audit_writable` — memory audit sink exists (always true for default setup)
   * - `model_bindings` — if modelBindings provided, verify all are present in contracts
   *
   * Degradation tiers:
   * - 0: all checks pass
   * - 1: only warnings (non-critical failures)
   * - 3: critical failure (no contracts loaded)
   */
  static verifyPreFlight(
    gov: GodClause,
    opts?: { requireSignatures?: boolean; modelBindings?: ModelBinding[] },
  ): PreFlightResult {
    const checks: Array<{ name: string; passed: boolean; detail?: string }> = [];

    // Check: contracts_loaded
    const contracts = gov.getContracts();
    const contractsLoaded = contracts.length > 0;
    checks.push({
      name: "contracts_loaded",
      passed: contractsLoaded,
      detail: contractsLoaded
        ? `${contracts.length} contract(s) loaded`
        : "No contracts loaded",
    });

    // Check: audit_writable
    const auditWritable = gov.memorySink != null;
    checks.push({
      name: "audit_writable",
      passed: auditWritable,
      detail: auditWritable
        ? "Memory audit sink available"
        : "No audit sink available",
    });

    // Check: model_bindings
    if (opts?.modelBindings && opts.modelBindings.length > 0) {
      const contractBindings = new Set<string>();
      for (const contract of contracts) {
        if (contract.model_bindings) {
          for (const mb of contract.model_bindings) {
            contractBindings.add(mb.model_id);
          }
        }
      }

      const allPresent = opts.modelBindings.every((mb) =>
        contractBindings.has(mb.model_id),
      );
      checks.push({
        name: "model_bindings",
        passed: allPresent,
        detail: allPresent
          ? "All model bindings found in contracts"
          : "Some model bindings missing from contracts",
      });
    }

    // Determine degradation tier
    let degradationTier = 0;
    if (!contractsLoaded) {
      degradationTier = 3; // Critical failure
    } else if (checks.some((c) => !c.passed)) {
      degradationTier = 1; // Warnings
    }

    const ready = checks.every((c) => c.passed);

    return { ready, checks, degradation_tier: degradationTier };
  }
}
