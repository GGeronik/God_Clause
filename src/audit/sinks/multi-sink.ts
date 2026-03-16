import { AuditSink } from "../audit-log";
import type { AuditEntry } from "../../types";

/**
 * Fan-out audit sink — writes every entry to multiple sinks simultaneously.
 *
 * ```ts
 * const multi = new MultiAuditSink([memorySink, fileSink, webhookSink, otelSink]);
 * ```
 */
export class MultiAuditSink implements AuditSink {
  private sinks: AuditSink[];

  constructor(sinks: AuditSink[]) {
    this.sinks = sinks;
  }

  async append(entry: AuditEntry): Promise<void> {
    await Promise.all(this.sinks.map((sink) => sink.append(entry)));
  }

  /** Add a sink at runtime. */
  addSink(sink: AuditSink): void {
    this.sinks.push(sink);
  }

  /** Remove a sink at runtime. */
  removeSink(sink: AuditSink): void {
    const idx = this.sinks.indexOf(sink);
    if (idx !== -1) this.sinks.splice(idx, 1);
  }
}
