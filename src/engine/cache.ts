import { createHash } from "crypto";
import type { PolicyContext, PolicyDecision } from "../types";

export interface CacheOptions {
  /** Time-to-live in milliseconds. Default: 5000 */
  ttlMs?: number;
  /** Maximum cache entries. Default: 1000 */
  maxSize?: number;
}

interface CacheEntry {
  decision: PolicyDecision;
  expiresAt: number;
}

/**
 * Decision cache — avoids re-evaluating identical contexts within a TTL window.
 *
 * Cache key is computed as SHA-256(canonicalized context). The cache is
 * automatically invalidated when contracts change (call `clear()`).
 *
 * ```ts
 * const cache = new DecisionCache({ ttlMs: 5000, maxSize: 1000 });
 * ```
 */
export class DecisionCache {
  private cache = new Map<string, CacheEntry>();
  private ttlMs: number;
  private maxSize: number;

  constructor(opts: CacheOptions = {}) {
    this.ttlMs = opts.ttlMs ?? 5000;
    this.maxSize = opts.maxSize ?? 1000;
  }

  /** Get a cached decision, or undefined if not found/expired. */
  get(ctx: PolicyContext): PolicyDecision | undefined {
    const key = this.computeKey(ctx);
    const entry = this.cache.get(key);
    if (!entry) return undefined;

    if (Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return undefined;
    }

    return entry.decision;
  }

  /** Cache a decision for a context. */
  set(ctx: PolicyContext, decision: PolicyDecision): void {
    // Evict oldest entries if at capacity
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) this.cache.delete(firstKey);
    }

    const key = this.computeKey(ctx);
    this.cache.set(key, {
      decision,
      expiresAt: Date.now() + this.ttlMs,
    });
  }

  /** Clear all cached decisions. Call this when contracts change. */
  clear(): void {
    this.cache.clear();
  }

  /** Number of entries currently cached. */
  get size(): number {
    return this.cache.size;
  }

  /** Cache hit rate statistics. */
  private computeKey(ctx: PolicyContext): string {
    // Exclude trace context from cache key (trace IDs change per request)
    const { trace, ...rest } = ctx;
    const keys = Object.keys(rest).sort();
    const payload = JSON.stringify(rest, keys);
    return createHash("sha256").update(payload).digest("hex");
  }
}
