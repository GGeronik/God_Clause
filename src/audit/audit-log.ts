import { createHash, createHmac, timingSafeEqual } from "crypto";
import { v4 as uuidv4 } from "uuid";
import { AuditChainAnchors, AuditEntry, AuditQuery, PolicyDecision, TrustContract } from "../types";

const GENESIS = "GENESIS";

export interface AuditSink {
  /** Entries arrive in chain order and delivery is awaited, so buffer network writes instead of blocking on them. */
  append(entry: AuditEntry): void | Promise<void>;
}

/**
 * Deterministic JSON: object keys sorted at every nesting level. Stable for hashing;
 * not RFC 8785 (integer-like keys keep JS enumeration order).
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(value, (_key, v) => {
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const obj = v as Record<string, unknown>;
      // Null prototype so an own "__proto__" key is serialized instead of hitting the setter.
      const sorted: Record<string, unknown> = Object.create(null);
      for (const k of Object.keys(obj).sort()) sorted[k] = obj[k];
      return sorted;
    }
    return v;
  });
}

/** SHA-256 over every field except `hash` and `hmac_signature`. */
export function hashAuditEntry(entry: AuditEntry): string {
  const { hash, hmac_signature, ...rest } = entry;
  return createHash("sha256").update(canonicalJson(rest)).digest("hex");
}

/** HMAC-SHA256 over every field except `hmac_signature`, so it also covers `hash`. */
export function signAuditEntry(entry: AuditEntry, secretKey: string): string {
  const { hmac_signature, ...rest } = entry;
  return createHmac("sha256", secretKey).update(canonicalJson(rest)).digest("hex");
}

function safeEqual(a: string, b: string): boolean {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}

/**
 * Verify hashes and links of a contiguous run of entries; with a key, every entry
 * also needs a valid hmac_signature. Anchors pin the first prev_hash and the last
 * hash; brokenAt === entries.length means the tail is missing.
 */
export function verifyAuditEntries(
  entries: AuditEntry[],
  secretKey?: string,
  anchors: AuditChainAnchors = {},
): { valid: boolean; brokenAt?: number } {
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    if (entry.hash !== hashAuditEntry(entry)) return { valid: false, brokenAt: i };
    if (i > 0 && entry.prev_hash !== entries[i - 1].hash) return { valid: false, brokenAt: i };
    if (
      secretKey !== undefined &&
      (!entry.hmac_signature || !safeEqual(entry.hmac_signature, signAuditEntry(entry, secretKey)))
    ) {
      return { valid: false, brokenAt: i };
    }
  }
  if (anchors.prevHash !== undefined && entries.length > 0 && entries[0].prev_hash !== anchors.prevHash) {
    return { valid: false, brokenAt: 0 };
  }
  if (anchors.headHash !== undefined && entries[entries.length - 1]?.hash !== anchors.headHash) {
    return { valid: false, brokenAt: entries.length };
  }
  return { valid: true };
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
  /** Hash of the last entry a previous process persisted; the chain continues from it instead of GENESIS. */
  headHash?: string;
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
  private readonly firstPrevHash: string;
  private lastHash: string;
  private entryCount = 0;
  private secretKey?: string;
  private permitSampleRate: number;
  private tail: Promise<void> = Promise.resolve();

  constructor(opts: AuditLogOptions = {}) {
    if (opts.secretKey === "") throw new Error("secretKey must not be empty");
    this.sinks = opts.sinks ?? [];
    this.secretKey = opts.secretKey;
    this.permitSampleRate = opts.permitSampleRate ?? 1.0;
    this.firstPrevHash = opts.headHash ?? GENESIS;
    this.lastHash = this.firstPrevHash;
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
  async record(decision: PolicyDecision, contract: TrustContract): Promise<AuditEntry | null> {
    // Sampling: always log denies and modifies, sample permits
    if (decision.outcome === "permit" && this.permitSampleRate < 1.0 && Math.random() >= this.permitSampleRate) {
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

    // Plain JSON only: no aliased caller object, no Date or boxed value that hashes differently once stored.
    const entry: AuditEntry = JSON.parse(
      JSON.stringify({
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
        obligations: decision.obligations.length > 0 ? decision.obligations.map((o) => o.obligation_id) : undefined,
        tags: allTags.size > 0 ? [...allTags] : undefined,
        tenant_id: decision.context.caller.tenant_id,
        trace_id: decision.context.trace?.trace_id,
        span_id: decision.context.trace?.span_id,
        parent_span_id: decision.context.trace?.parent_span_id,
        policy_sha256: decision.governance_context?.policy_sha256,
        timestamp: decision.timestamp,
        prev_hash: this.lastHash,
        hash: "",
        hash_version: 3,
      }),
    );

    entry.hash = hashAuditEntry(entry);
    if (this.secretKey) {
      entry.hmac_signature = signAuditEntry(entry, this.secretKey);
    }
    this.lastHash = entry.hash;
    this.entryCount++;

    // Sinks get entries in chain order even when decisions overlap, each its own copy; a failing sink
    // does not stop delivery to the others.
    const json = JSON.stringify(entry);
    const run = this.tail.then(async () => {
      let failure: unknown;
      for (const sink of this.sinks) {
        try {
          await sink.append(JSON.parse(json));
        } catch (err) {
          failure ??= err;
        }
      }
      if (failure !== undefined) throw failure;
    });
    this.tail = run.catch(() => undefined);
    await run;

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
      results = results.filter((e) => e.rule_results.some((r) => r.rule_id === query.rule_id));
    }
    if (query.tags?.length) {
      results = results.filter((e) => e.tags?.some((t) => query.tags!.includes(t)));
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
   * Verify the complete chain this log produced: the first entry must link to where
   * this log started (GENESIS or the configured headHash) and, once anything was
   * recorded, the last entry must be the current head.
   */
  verifyChain(entries: AuditEntry[], secretKey?: string): { valid: boolean; brokenAt?: number } {
    return verifyAuditEntries(entries, secretKey ?? this.secretKey, {
      prevHash: this.firstPrevHash,
      headHash: this.entryCount > 0 ? this.lastHash : undefined,
    });
  }

  /** Hash of the most recently recorded entry. Persist it to anchor the tail of the chain. */
  get headHash(): string {
    return this.lastHash;
  }
}
