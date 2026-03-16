import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { Logger } from "../src/observability/logger";
import { OTelAuditSink } from "../src/observability/otel-sink";
import type { AuditEntry } from "../src/types";

function makeEntry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    entry_id: "e-1",
    decision_id: "d-1",
    timestamp: "2026-03-15T12:00:00Z",
    contract_name: "Test",
    contract_version: "1.0.0",
    action: "generate",
    allowed: true,
    outcome: "permit",
    blocks: [],
    warnings: [],
    hash: "abc123",
    previous_hash: "000000",
    caller: { user_id: "u1", session_id: "s1", roles: [] },
    input_classification: "public",
    ...overrides,
  };
}

describe("Logger", () => {
  let stdoutSpy: ReturnType<typeof vi.spyOn>;
  let stderrSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    stdoutSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    stderrSpy = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  });

  afterEach(() => {
    stdoutSpy.mockRestore();
    stderrSpy.mockRestore();
  });

  it("outputs structured JSON to stdout", () => {
    const logger = new Logger({ level: "debug", service: "test" });
    logger.info("hello", { key: "val" });

    expect(stdoutSpy).toHaveBeenCalledTimes(1);
    const output = JSON.parse((stdoutSpy.mock.calls[0][0] as string).trim());
    expect(output.level).toBe("info");
    expect(output.msg).toBe("hello");
    expect(output.key).toBe("val");
    expect(output.service).toBe("test");
    expect(output.ts).toBeTruthy();
  });

  it("writes errors to stderr", () => {
    const logger = new Logger({ level: "debug" });
    logger.error("something broke", { code: 500 });

    expect(stderrSpy).toHaveBeenCalledTimes(1);
    const output = JSON.parse((stderrSpy.mock.calls[0][0] as string).trim());
    expect(output.level).toBe("error");
    expect(output.code).toBe(500);
  });

  it("respects log level filtering", () => {
    const logger = new Logger({ level: "warn" });
    logger.debug("hidden");
    logger.info("hidden");
    logger.warn("visible");

    expect(stdoutSpy).toHaveBeenCalledTimes(1);
    const output = JSON.parse((stdoutSpy.mock.calls[0][0] as string).trim());
    expect(output.msg).toBe("visible");
  });

  it("defaults to info level", () => {
    const logger = new Logger();
    logger.debug("hidden");
    logger.info("visible");

    expect(stdoutSpy).toHaveBeenCalledTimes(1);
  });

  it("uses LOG_LEVEL env var", () => {
    const original = process.env.LOG_LEVEL;
    process.env.LOG_LEVEL = "error";

    const logger = new Logger();
    logger.info("hidden");
    logger.warn("hidden");
    logger.error("visible");

    expect(stdoutSpy).toHaveBeenCalledTimes(0);
    expect(stderrSpy).toHaveBeenCalledTimes(1);

    process.env.LOG_LEVEL = original;
  });
});

describe("OTelAuditSink", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("buffers entries and flushes on batch size", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const sink = new OTelAuditSink({
      endpoint: "http://localhost:4318/v1/logs",
      batchSize: 2,
      flushIntervalMs: 60000, // long interval so flush is triggered by batch
    });

    sink.append(makeEntry());
    expect(fetchMock).not.toHaveBeenCalled();

    sink.append(makeEntry({ entry_id: "e-2" }));
    // Wait for the async flush
    await new Promise((r) => setTimeout(r, 50));

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const call = fetchMock.mock.calls[0];
    expect(call[0]).toBe("http://localhost:4318/v1/logs");
    expect(call[1].method).toBe("POST");

    const body = JSON.parse(call[1].body);
    expect(body.resourceLogs[0].resource.attributes[0].value.stringValue).toBe("god-clause");
    expect(body.resourceLogs[0].scopeLogs[0].logRecords).toHaveLength(2);

    sink.stop();
  });

  it("maps severity correctly", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const sink = new OTelAuditSink({
      endpoint: "http://localhost:4318/v1/logs",
      batchSize: 1,
      flushIntervalMs: 60000,
    });

    sink.append(makeEntry({ outcome: "deny", allowed: false }));
    await new Promise((r) => setTimeout(r, 50));

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const record = body.resourceLogs[0].scopeLogs[0].logRecords[0];
    expect(record.severityText).toBe("ERROR");
    expect(record.severityNumber).toBe(17);

    sink.stop();
  });

  it("includes attributes from audit entry", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const sink = new OTelAuditSink({
      endpoint: "http://localhost:4318/v1/logs",
      batchSize: 1,
      flushIntervalMs: 60000,
    });

    sink.append(makeEntry({ blocks: ["R-001", "R-002"], tenant_id: "t1" }));
    await new Promise((r) => setTimeout(r, 50));

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    const record = body.resourceLogs[0].scopeLogs[0].logRecords[0];
    const attrs = Object.fromEntries(record.attributes.map((a: any) => [a.key, a.value]));

    expect(attrs["godclause.entry_id"].stringValue).toBe("e-1");
    expect(attrs["godclause.tenant_id"].stringValue).toBe("t1");
    expect(attrs["godclause.blocked_rules"].stringValue).toBe("R-001,R-002");

    sink.stop();
  });

  it("re-queues entries on fetch failure", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("network"));
    vi.stubGlobal("fetch", fetchMock);

    const sink = new OTelAuditSink({
      endpoint: "http://localhost:4318/v1/logs",
      batchSize: 1,
      flushIntervalMs: 60000,
    });

    sink.append(makeEntry());
    await new Promise((r) => setTimeout(r, 50));

    // Entry should be re-queued, so a manual flush should retry
    fetchMock.mockResolvedValue({ ok: true });
    await sink.flush();

    expect(fetchMock).toHaveBeenCalledTimes(2);

    sink.stop();
  });

  it("sends custom headers", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const sink = new OTelAuditSink({
      endpoint: "http://localhost:4318/v1/logs",
      headers: { "X-API-Key": "secret123" },
      batchSize: 1,
      flushIntervalMs: 60000,
    });

    sink.append(makeEntry());
    await new Promise((r) => setTimeout(r, 50));

    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["X-API-Key"]).toBe("secret123");

    sink.stop();
  });
});
