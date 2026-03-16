import { AuditSink } from "../audit/audit-log";
import type { AuditEntry } from "../types";

export interface OTelSinkOptions {
  /** OTLP/HTTP endpoint (e.g., "http://localhost:4318/v1/logs") */
  endpoint: string;
  /** Service name for OTel Resource */
  serviceName?: string;
  /** Additional headers (e.g., API keys) */
  headers?: Record<string, string>;
  /** Batch size before flush. Default: 50 */
  batchSize?: number;
  /** Flush interval in ms. Default: 5000 */
  flushIntervalMs?: number;
}

interface OTelLogRecord {
  timeUnixNano: string;
  severityNumber: number;
  severityText: string;
  body: { stringValue: string };
  attributes: Array<{ key: string; value: { stringValue?: string; boolValue?: boolean; intValue?: number } }>;
  traceId?: string;
  spanId?: string;
}

/**
 * OpenTelemetry-compatible audit sink that exports audit entries as OTLP log records.
 *
 * Maps audit entries to the OpenTelemetry logs data model and exports
 * via OTLP/HTTP protocol for integration with any OTel-compatible backend
 * (Datadog, New Relic, Grafana, Splunk, etc.).
 */
export class OTelAuditSink implements AuditSink {
  private buffer: OTelLogRecord[] = [];
  private endpoint: string;
  private serviceName: string;
  private headers: Record<string, string>;
  private batchSize: number;
  private flushIntervalMs: number;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(opts: OTelSinkOptions) {
    this.endpoint = opts.endpoint;
    this.serviceName = opts.serviceName ?? "god-clause";
    this.headers = opts.headers ?? {};
    this.batchSize = opts.batchSize ?? 50;
    this.flushIntervalMs = opts.flushIntervalMs ?? 5000;

    this.timer = setInterval(() => this.flush(), this.flushIntervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  append(entry: AuditEntry): void {
    const record = this.mapToLogRecord(entry);
    this.buffer.push(record);

    if (this.buffer.length >= this.batchSize) {
      this.flush().catch(() => {});
    }
  }

  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;

    const records = this.buffer.splice(0);
    const payload = {
      resourceLogs: [
        {
          resource: {
            attributes: [
              { key: "service.name", value: { stringValue: this.serviceName } },
            ],
          },
          scopeLogs: [
            {
              scope: { name: "god-clause.audit", version: "2.0.0" },
              logRecords: records,
            },
          ],
        },
      ],
    };

    try {
      const response = await fetch(this.endpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...this.headers,
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        // Re-queue on failure
        this.buffer.unshift(...records);
      }
    } catch {
      // Re-queue on network failure
      this.buffer.unshift(...records);
    }
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private mapToLogRecord(entry: AuditEntry): OTelLogRecord {
    const severityMap: Record<string, { number: number; text: string }> = {
      permit: { number: 9, text: "INFO" },
      deny: { number: 17, text: "ERROR" },
      modify: { number: 13, text: "WARN" },
    };

    const severity = severityMap[entry.outcome ?? (entry.allowed ? "permit" : "deny")];
    const tsNano = BigInt(new Date(entry.timestamp).getTime()) * 1000000n;

    const attributes: OTelLogRecord["attributes"] = [
      { key: "godclause.entry_id", value: { stringValue: entry.entry_id } },
      { key: "godclause.decision_id", value: { stringValue: entry.decision_id } },
      { key: "godclause.contract_name", value: { stringValue: entry.contract_name } },
      { key: "godclause.contract_version", value: { stringValue: entry.contract_version } },
      { key: "godclause.action", value: { stringValue: entry.action } },
      { key: "godclause.allowed", value: { boolValue: entry.allowed } },
      { key: "godclause.user_id", value: { stringValue: entry.caller.user_id } },
    ];

    if (entry.outcome) {
      attributes.push({ key: "godclause.outcome", value: { stringValue: entry.outcome } });
    }
    if (entry.tenant_id) {
      attributes.push({ key: "godclause.tenant_id", value: { stringValue: entry.tenant_id } });
    }
    if (entry.policy_sha256) {
      attributes.push({ key: "godclause.policy_sha256", value: { stringValue: entry.policy_sha256 } });
    }
    if (entry.blocks.length > 0) {
      attributes.push({ key: "godclause.blocked_rules", value: { stringValue: entry.blocks.join(",") } });
    }

    return {
      timeUnixNano: tsNano.toString(),
      severityNumber: severity.number,
      severityText: severity.text,
      body: { stringValue: JSON.stringify(entry) },
      attributes,
      traceId: entry.trace_id,
      spanId: entry.span_id,
    };
  }
}
