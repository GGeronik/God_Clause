import { createHmac } from "crypto";
import { AuditSink } from "../audit-log";
import type { AuditEntry } from "../../types";

export interface WebhookSinkOptions {
  /** URL to POST audit entries to */
  url: string;
  /** Additional headers (e.g., API keys) */
  headers?: Record<string, string>;
  /** HMAC-SHA256 secret for signing webhook payloads */
  secret?: string;
  /** Number of entries to batch before sending. Default: 10 */
  batchSize?: number;
  /** Max interval between flushes in ms. Default: 5000 */
  flushIntervalMs?: number;
}

/**
 * Webhook audit sink — posts batched audit entries to any HTTP endpoint.
 *
 * When a `secret` is configured, each request includes an `X-GodClause-Signature`
 * header with an HMAC-SHA256 signature of the request body.
 */
export class WebhookAuditSink implements AuditSink {
  private buffer: AuditEntry[] = [];
  private url: string;
  private headers: Record<string, string>;
  private secret?: string;
  private batchSize: number;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(opts: WebhookSinkOptions) {
    this.url = opts.url;
    this.headers = opts.headers ?? {};
    this.secret = opts.secret;
    this.batchSize = opts.batchSize ?? 10;

    const intervalMs = opts.flushIntervalMs ?? 5000;
    this.timer = setInterval(() => this.flush(), intervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  append(entry: AuditEntry): void {
    this.buffer.push(entry);
    if (this.buffer.length >= this.batchSize) {
      this.flush().catch(() => {});
    }
  }

  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const entries = this.buffer.splice(0);
    const body = JSON.stringify({ entries });

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...this.headers,
    };

    if (this.secret) {
      const signature = createHmac("sha256", this.secret).update(body).digest("hex");
      headers["X-GodClause-Signature"] = `sha256=${signature}`;
    }

    try {
      await fetch(this.url, {
        method: "POST",
        headers,
        body,
      });
    } catch {
      // Re-queue on failure
      this.buffer.unshift(...entries);
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }
}
