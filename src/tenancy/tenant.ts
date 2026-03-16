import {
  TrustContract,
  PolicyContext,
  PolicyDecision,
  AuditEntry,
  AuditQuery,
  EvaluateOptions,
} from "../types";
import { parseContract } from "../contracts/parser";
import { ContractRegistry } from "../contracts/registry";
import { PolicyEngine, PolicyEngineOptions } from "../engine/policy-engine";
import { AuditLog, MemoryAuditSink, AuditSink } from "../audit/audit-log";
import { ChainSeal, computeMerkleRoot } from "../audit/seal";
import type { StateStore } from "../engine/state-store";

export interface TenantOptions extends PolicyEngineOptions {
  /** Tenant display name. */
  tenantName?: string;
  /** Audit sinks for this tenant. Defaults to a MemoryAuditSink. */
  auditSinks?: AuditSink[];
  /** Secret key for HMAC signing of this tenant's audit entries. */
  auditSecretKey?: string;
  /** State store for rate limiting. */
  stateStore?: StateStore;
}

/**
 * An isolated tenant scope with its own contract registry, policy engine,
 * and audit log. Provides the same API surface as GodClause but scoped
 * to a single tenant.
 */
export class TenantScope {
  readonly tenantId: string;
  readonly tenantName?: string;
  readonly registry: ContractRegistry;
  readonly engine: PolicyEngine;
  readonly auditLog: AuditLog;
  readonly memorySink: MemoryAuditSink;

  private lastSealIndex = 0;

  constructor(tenantId: string, opts: TenantOptions = {}) {
    this.tenantId = tenantId;
    this.tenantName = opts.tenantName;
    this.registry = new ContractRegistry();

    this.memorySink = new MemoryAuditSink();
    const sinks = opts.auditSinks ?? [this.memorySink];
    this.auditLog = new AuditLog({
      sinks,
      secretKey: opts.auditSecretKey,
    });

    const userOnDecision = opts.onDecision;
    const self = this;

    this.engine = new PolicyEngine({
      ...opts,
      async onDecision(decision) {
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

  /** Parse and load a trust contract from YAML/JSON. */
  loadContractYAML(source: string): TrustContract {
    const contract = parseContract(source);
    this.registry.register(contract, { activate: true });
    this.engine.loadContract(contract);
    return contract;
  }

  /** Load an already-parsed contract. */
  loadContract(contract: TrustContract): void {
    this.registry.register(contract, { activate: true });
    this.engine.loadContract(contract);
  }

  /** Evaluate a context, injecting tenant_id into the caller. */
  async evaluate(ctx: PolicyContext, opts?: EvaluateOptions): Promise<PolicyDecision> {
    const enrichedCtx = this.enrichContext(ctx);
    return this.engine.evaluate(enrichedCtx, opts);
  }

  /** Evaluate and throw if blocked. */
  async enforce(ctx: PolicyContext, opts?: EvaluateOptions): Promise<PolicyDecision> {
    const enrichedCtx = this.enrichContext(ctx);
    return this.engine.enforce(enrichedCtx, opts);
  }

  queryAudit(query: AuditQuery): AuditEntry[] {
    return this.auditLog.query(this.memorySink, query);
  }

  getAuditEntries(): ReadonlyArray<AuditEntry> {
    return this.memorySink.entries;
  }

  verifyAuditChain(secretKey?: string): { valid: boolean; brokenAt?: number } {
    return this.auditLog.verifyChain(this.memorySink.entries, secretKey);
  }

  sealAuditChain(): ChainSeal {
    const entries = this.memorySink.entries.slice(this.lastSealIndex);
    if (entries.length === 0) throw new Error("No new audit entries to seal");
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

  verifyAuditSeal(seal: ChainSeal): boolean {
    const fromIdx = this.memorySink.entries.findIndex((e) => e.entry_id === seal.from_entry_id);
    const toIdx = this.memorySink.entries.findIndex((e) => e.entry_id === seal.to_entry_id);
    if (fromIdx === -1 || toIdx === -1 || toIdx < fromIdx) return false;
    const entries = this.memorySink.entries.slice(fromIdx, toIdx + 1);
    if (entries.length !== seal.entry_count) return false;
    const hashes = entries.map((e) => e.hash);
    return computeMerkleRoot(hashes) === seal.merkle_root;
  }

  private enrichContext(ctx: PolicyContext): PolicyContext {
    return {
      ...ctx,
      caller: {
        ...ctx.caller,
        tenant_id: this.tenantId,
      },
    };
  }
}
