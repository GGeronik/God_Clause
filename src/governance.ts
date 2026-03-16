import { TrustContract, PolicyContext, PolicyDecision, AuditEntry, AuditQuery, EvaluateOptions } from "./types";
import { parseContract, serializeContract, summarizeContract } from "./contracts/parser";
import { ContractRegistry } from "./contracts/registry";
import { PolicyEngine, PolicyEngineOptions, PolicyViolationError } from "./engine/policy-engine";
import { AuditLog, MemoryAuditSink, AuditSink } from "./audit/audit-log";
import { ChainSeal, computeMerkleRoot } from "./audit/seal";
import { TenantScope, TenantOptions } from "./tenancy/tenant";
import type { StateStore } from "./engine/state-store";

export interface GovernanceOptions extends PolicyEngineOptions {
  /** Audit sinks to attach. Defaults to a single MemoryAuditSink. */
  auditSinks?: AuditSink[];
  /** Secret key for HMAC-SHA256 audit signing. */
  auditSecretKey?: string;
  /** State store for rate limiting conditions. */
  stateStore?: StateStore;
}

/**
 * GodClause — the unified governance orchestrator.
 *
 * Combines trust contracts, runtime policy enforcement, and
 * tamper-evident audit logging into a single embeddable API.
 *
 * ```ts
 * const gov = new GodClause();
 * gov.loadContractYAML(yamlString);
 * const decision = await gov.evaluate(context);
 * ```
 */
export class GodClause {
  readonly engine: PolicyEngine;
  readonly auditLog: AuditLog;
  readonly memorySink: MemoryAuditSink;
  readonly registry: ContractRegistry;

  private lastSealIndex = 0;
  private tenants = new Map<string, TenantScope>();

  constructor(opts: GovernanceOptions = {}) {
    this.memorySink = new MemoryAuditSink();
    this.registry = new ContractRegistry();
    const sinks = opts.auditSinks ?? [this.memorySink];
    this.auditLog = new AuditLog({
      sinks,
      secretKey: opts.auditSecretKey,
    });

    // Wrap the user's onDecision hook to also record audits.
    const userOnDecision = opts.onDecision;
    const self = this;

    this.engine = new PolicyEngine({
      ...opts,
      async onDecision(decision) {
        // Record in audit log for every active contract.
        for (const contract of self.registry.getAllActive()) {
          await self.auditLog.record(decision, contract);
        }
        if (userOnDecision) await userOnDecision(decision);
      },
    });

    if (opts.stateStore) {
      this.engine.setStateStore(opts.stateStore);
    }
  }

  // ─── Contract Management ─────────────────────────────────────────

  /** Parse and load a trust contract from a YAML or JSON string. */
  loadContractYAML(source: string): TrustContract {
    const contract = parseContract(source);
    this.registry.register(contract, { activate: true });
    this.engine.loadContract(contract);
    return contract;
  }

  /** Load an already-parsed trust contract object. */
  loadContract(contract: TrustContract): void {
    this.registry.register(contract, { activate: true });
    this.engine.loadContract(contract);
  }

  /** Load a contract version without necessarily activating it. */
  loadContractVersion(source: string, opts: { activate?: boolean } = {}): TrustContract {
    const contract = parseContract(source);
    this.registry.register(contract, { activate: opts.activate });
    if (opts.activate !== false) {
      this.engine.loadContract(contract);
    }
    return contract;
  }

  /** Activate a specific contract version. */
  activateContract(name: string, version: string): void {
    this.registry.activate(name, version);
    // Rebuild engine contracts from registry
    this.syncEngineContracts();
  }

  /** Deactivate a specific contract version. */
  deactivateContract(name: string, version: string): void {
    this.registry.deactivate(name, version);
    this.syncEngineContracts();
  }

  /** List all versions of a contract. */
  getContractVersions(name: string): Array<{ name: string; versions: string[]; activeVersion: string | null }> {
    return this.registry.list().filter((entry) => entry.name === name);
  }

  /** Get all loaded contracts (active only). */
  getContracts(): ReadonlyArray<TrustContract> {
    return this.registry.getAllActive();
  }

  /** Serialize a contract back to YAML. */
  toYAML(contract: TrustContract): string {
    return serializeContract(contract);
  }

  /** Get a plain-language summary of a contract. */
  summarize(contract: TrustContract): string {
    return summarizeContract(contract);
  }

  private syncEngineContracts(): void {
    this.engine.clearContracts();
    for (const contract of this.registry.getAllActive()) {
      this.engine.loadContract(contract);
    }
  }

  // ─── Policy Enforcement ──────────────────────────────────────────

  /**
   * Evaluate a context against all loaded contracts.
   * Returns the decision without throwing.
   */
  async evaluate(ctx: PolicyContext, opts?: EvaluateOptions): Promise<PolicyDecision> {
    return this.engine.evaluate(ctx, opts);
  }

  /**
   * Evaluate and throw PolicyViolationError if any blocking rule fails.
   */
  async enforce(ctx: PolicyContext, opts?: EvaluateOptions): Promise<PolicyDecision> {
    return this.engine.enforce(ctx, opts);
  }

  // ─── Audit Queries ───────────────────────────────────────────────

  /** Query the in-memory audit log. */
  queryAudit(query: AuditQuery): AuditEntry[] {
    return this.auditLog.query(this.memorySink, query);
  }

  /** Verify the hash-chain integrity of audit entries. */
  verifyAuditChain(secretKey?: string): { valid: boolean; brokenAt?: number } {
    return this.auditLog.verifyChain(this.memorySink.entries, secretKey);
  }

  /** Get all audit entries. */
  getAuditEntries(): ReadonlyArray<AuditEntry> {
    return this.memorySink.entries;
  }

  // ─── Audit Sealing ───────────────────────────────────────────────

  /**
   * Create a Merkle seal checkpoint over audit entries recorded
   * since the last seal (or from the beginning).
   */
  sealAuditChain(): ChainSeal {
    const entries = this.memorySink.entries.slice(this.lastSealIndex);
    if (entries.length === 0) {
      throw new Error("No new audit entries to seal");
    }

    const hashes = entries.map((e) => e.hash);
    const seal: ChainSeal = {
      seal_id: entries[entries.length - 1].entry_id + ":seal",
      from_entry_id: entries[0].entry_id,
      to_entry_id: entries[entries.length - 1].entry_id,
      entry_count: entries.length,
      merkle_root: computeMerkleRoot(hashes),
      timestamp: new Date().toISOString(),
    };

    this.lastSealIndex = this.memorySink.entries.length;
    return seal;
  }

  /**
   * Verify a previously created Merkle seal against current audit entries.
   */
  verifyAuditSeal(seal: ChainSeal): boolean {
    const fromIdx = this.memorySink.entries.findIndex((e) => e.entry_id === seal.from_entry_id);
    const toIdx = this.memorySink.entries.findIndex((e) => e.entry_id === seal.to_entry_id);
    if (fromIdx === -1 || toIdx === -1 || toIdx < fromIdx) return false;

    const entries = this.memorySink.entries.slice(fromIdx, toIdx + 1);
    if (entries.length !== seal.entry_count) return false;

    const hashes = entries.map((e) => e.hash);
    return computeMerkleRoot(hashes) === seal.merkle_root;
  }

  // ─── Multi-Tenancy ───────────────────────────────────────────────

  /** Create an isolated tenant scope. */
  createTenant(tenantId: string, opts?: TenantOptions): TenantScope {
    if (this.tenants.has(tenantId)) {
      throw new Error(`Tenant "${tenantId}" already exists`);
    }
    const tenant = new TenantScope(tenantId, opts);
    this.tenants.set(tenantId, tenant);
    return tenant;
  }

  /** Get an existing tenant scope. */
  getTenant(tenantId: string): TenantScope | undefined {
    return this.tenants.get(tenantId);
  }

  /** Remove a tenant scope. */
  removeTenant(tenantId: string): boolean {
    return this.tenants.delete(tenantId);
  }

  /** Query audit entries across all tenants. */
  queryAllTenantsAudit(query: AuditQuery): AuditEntry[] {
    const results: AuditEntry[] = [];
    for (const tenant of this.tenants.values()) {
      results.push(...tenant.queryAudit(query));
    }
    // Sort by timestamp
    results.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    if (query.offset) results.splice(0, query.offset);
    if (query.limit) results.splice(query.limit);
    return results;
  }
}
