/**
 * State store interface for stateful condition operators like rate_limit.
 * Implement against Redis, DynamoDB, etc. for production use.
 */
export interface StateStore {
  /** Record an event and return the current count within the window. */
  recordAndCount(key: string, windowMs: number): Promise<number>;
  /** Get the current count within the window without recording. */
  getCount(key: string, windowMs: number): Promise<number>;
  /** Clear all stored state. */
  clear(): Promise<void>;
}

/**
 * In-memory state store using sliding window counters.
 * Suitable for single-process use and testing.
 */
export class MemoryStateStore implements StateStore {
  private buckets = new Map<string, number[]>();

  async recordAndCount(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const timestamps = this.getBucket(key);
    timestamps.push(now);
    this.prune(timestamps, now, windowMs);
    return timestamps.length;
  }

  async getCount(key: string, windowMs: number): Promise<number> {
    const now = Date.now();
    const timestamps = this.getBucket(key);
    this.prune(timestamps, now, windowMs);
    return timestamps.length;
  }

  async clear(): Promise<void> {
    this.buckets.clear();
  }

  private getBucket(key: string): number[] {
    let bucket = this.buckets.get(key);
    if (!bucket) {
      bucket = [];
      this.buckets.set(key, bucket);
    }
    return bucket;
  }

  private prune(timestamps: number[], now: number, windowMs: number): void {
    const cutoff = now - windowMs;
    while (timestamps.length > 0 && timestamps[0] <= cutoff) {
      timestamps.shift();
    }
  }
}

/**
 * Parse a subset of ISO 8601 durations to milliseconds.
 * Supports: PT1H, PT30M, PT5S, PT1H30M, PT1H30M15S, P1D, P7D, etc.
 */
export function parseISO8601Duration(duration: string): number {
  const match = duration.match(
    /^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$/,
  );
  if (!match) {
    throw new Error(`Invalid ISO 8601 duration: ${duration}`);
  }

  const days = parseInt(match[1] || "0", 10);
  const hours = parseInt(match[2] || "0", 10);
  const minutes = parseInt(match[3] || "0", 10);
  const seconds = parseInt(match[4] || "0", 10);

  return ((days * 24 + hours) * 60 + minutes) * 60000 + seconds * 1000;
}
