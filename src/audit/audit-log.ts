import { createHash, createHmac } from "crypto";
import { v4 as uuidv4 } from "uuid";
import {
  AuditEntry,
  AuditQuery,
  PolicyDecision,
  TrustContract,
} from "../types";

export interface AuditSink {
  append(entry: AuditEntry): void | Promise<void>;
}

/**
 * In-memory audit sink. Suitable for testing and lightweight use.
 * For production, implement AuditSink against your durable store.
 */
export class MemoryAuditSink implements AuditSink {
  readonly entries: AuditEntry[] = [];

  append(entry: AuditEntry): void {
    this.entries.push(entry);
  }
}

export interface AuditLogOptions {
  sinks?: AuditSink[];
  /** Secret key for HMAC-SHA256 signing. When set, each entry gets a tamper-proof signature. */
  secretKey?: string;
  /**
   * Sampling rate for permit decisions (0.0 - 1.0, default 1.0).
   * Deny and modify decisions are ALWAYS logged regardless of this setting.
   * At high throughput, set to 0.1 to log ~10% of permits while capturing every violation.
   */
  permitSampleRate?: number;
}

/**
 * The AuditLog provides tamper-evident, append-only logging of every
 * policy decision. Each entry contains a SHA-256 hash chain linking
 * it to the previous entry, making retroactive modification detectable.
 *
 * When a secretKey is configured, entries also receive an HMAC-SHA256
 * signature that prevents hash recomputation attacks.
 */
export class AuditLog {
  private sinks: AuditSink[] = [];
  private lastHash: string = "GENESIS";
  private entryCount = 0;
  private secretKey?: string;
  private permitSampleRate: number;

  constructor(opts: AuditLogOptions = {}) {
    this.sinks = opts.sinks ?? [];
    this.secretKey = opts.secretKey;
    this.permitSampleRate = opts.permitSampleRate ?? 1.0;
  }

  /** Add an audit sink (database, file, webhook, etc.). */
  addSink(sink: AuditSink): void {
    this.sinks.push(sink);
  }

  /**
   * Record a policy decision as an immutable audit entry.
   * When permitSampleRate < 1.0, permit decisions may be randomly skipped
   * to reduce volume. Deny and modify decisions are ALWAYS recorded.
   * Returns null when a permit is skipped due to sampling.
   */
  async record(
    decision: PolicyDecision,
    contract: TrustContract,
  ): Promise<AuditEntry | null> {
    // Sampling: always log denies and modifies, sample permits
    if (
      decision.outcome === "permit" &&
      this.permitSampleRate < 1.0 &&
      Math.random() >= this.permitSampleRate
    ) {
      return null;
    }

    // Collect tags from evaluated rules
    const allTags = new Set<string>();
    for (const e of decision.evaluations) {
      const rule = contract.rules.find((r) => r.id === e.rule_id);
      if (rule?.tags) {
        for (const t of rule.tags) allTags.add(t);
      }
    }

    const entry: AuditEntry = {
      entry_id: uuidv4(),
      decision_id: decision.decision_id,
      contract_name: contract.metadata.name,
      contract_version: contract.metadata.version,
      action: decision.context.action,
      caller: decision.context.caller,
      allowed: decision.allowed,
      outcome: decision.outcome,
      rule_results: decision.evaluations.map((e) => ({
        rule_id: e.rule_id,
        passed: e.passed,
        severity: e.severity,
      })),
      warnings: decision.warnings.map((w) => w.rule_id),
      blocks: decision.blocks.map((b) => b.rule_id),
      logs: decision.logs.map((l) => l.rule_id),
      obligations: decision.obligations.length > 0
        ? decision.obligations.map((o) => o.obligation_id)
        : undefined,
      tags: allTags.size > 0 ? [...allTags] : undefined,
      tenant_id: decision.context.caller.tenant_id,
      trace_id: decision.context.trace?.trace_id,
      span_id: decision.context.trace?.span_id,
      parent_span_id: decision.context.trace?.parent_span_id,
      policy_sha256: decision.governance_context?.policy_sha256,
      timestamp: decision.timestamp,
      prev_hash: this.lastHash,
      hash: "",
      hash_version: 2,
    };

    entry.hash = this.computeHash(entry);
    if (this.secretKey) {
      entry.hmac_signature = this.computeHmac(entry);
    }
    this.lastHash = entry.hash;
    this.entryCount++;

    for (const sink of this.sinks) {
      await sink.append(entry);
    }

    return entry;
  }

  /** Number of entries recorded in this session. */
  get count(): number {
    return this.entryCount;
  }

  /**
   * Query entries from a MemoryAuditSink. For custom sinks,
   * implement query logic in your sink's storage layer.
   */
  query(sink: MemoryAuditSink, query: AuditQuery): AuditEntry[] {
    let results = [...sink.entries];

    if (query.from) {
      const from = new Date(query.from).getTime();
      results = results.filter((e) => new Date(e.timestamp).getTime() >= from);
    }
    if (query.to) {
      const to = new Date(query.to).getTime();
      results = results.filter((e) => new Date(e.timestamp).getTime() <= to);
    }
    if (query.action) {
      results = results.filter((e) => e.action === query.action);
    }
    if (query.user_id) {
      results = results.filter((e) => e.caller.user_id === query.user_id);
    }
    if (query.allowed !== undefined) {
      results = results.filter((e) => e.allowed === query.allowed);
    }
    if (query.rule_id) {
      results = results.filter((e) =>
        e.rule_results.some((r) => r.rule_id === query.rule_id),
      );
    }
    if (query.tags?.length) {
      results = results.filter((e) =>
        e.tags?.some((t) => query.tags!.includes(t)),
      );
    }
    if (query.tenant_id) {
      results = results.filter((e) => e.tenant_id === query.tenant_id);
    }
    if (query.trace_id) {
      results = results.filter((e) => e.trace_id === query.trace_id);
    }
    if (query.parent_span_id) {
      results = results.filter((e) => e.parent_span_id === query.parent_span_id);
    }
    if (query.offset) {
      results = results.slice(query.offset);
    }
    if (query.limit) {
      results = results.slice(0, query.limit);
    }

    return results;
  }

  /**
   * Verify the integrity of a chain of audit entries.
   * Optionally verify HMAC signatures when a secret key is provided.
   */
  verifyChain(
    entries: AuditEntry[],
    secretKey?: string,
  ): { valid: boolean; brokenAt?: number } {
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      const expected = this.computeHash(entry);
      if (entry.hash !== expected) {
        return { valid: false, brokenAt: i };
      }
      if (i > 0 && entry.prev_hash !== entries[i - 1].hash) {
        return { valid: false, brokenAt: i };
      }
      // Verify HMAC if key is available
      const key = secretKey ?? this.secretKey;
      if (key && entry.hmac_signature) {
        const expectedHmac = this.computeHmacWith(entry, key);
        if (entry.hmac_signature !== expectedHmac) {
          return { valid: false, brokenAt: i };
        }
      }
    }
    return { valid: true };
  }

  /**
   * Compute a SHA-256 hash over all entry fields except `hash` and `hmac_signature`.
   * Uses sorted keys for deterministic serialization.
   */
  private computeHash(entry: AuditEntry): string {
    const { hash, hmac_signature, ...rest } = entry;
    const keys = Object.keys(rest).sort();
    const payload = JSON.stringify(rest, keys);
    return createHash("sha256").update(payload).digest("hex");
  }

  private computeHmac(entry: AuditEntry): string {
    return this.computeHmacWith(entry, this.secretKey!);
  }

  private computeHmacWith(entry: AuditEntry, key: string): string {
    // HMAC covers the full entry including hash but excluding hmac_signature
    const { hmac_signature, ...rest } = entry;
    const keys = Object.keys(rest).sort();
    const payload = JSON.stringify(rest, keys);
    return createHmac("sha256", key).update(payload).digest("hex");
  }
}
