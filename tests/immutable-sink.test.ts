import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createHash } from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { AuditEntry } from "../src/types";
import { AuditSink } from "../src/audit/audit-log";
import {
  ImmutableAuditSink,
  ImmutabilityViolationError,
} from "../src/audit/sinks/immutable-sink";

let tmpDir: string;

beforeEach(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "immutable-sink-test-"));
});

afterEach(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function makeEntry(id: string): AuditEntry {
  const entry: AuditEntry = {
    entry_id: id,
    decision_id: `decision-${id}`,
    contract_name: "Test",
    contract_version: "1.0.0",
    action: "generate",
    caller: { user_id: "u1", session_id: "s1", roles: ["admin"] },
    allowed: true,
    outcome: "permit",
    rule_results: [],
    warnings: [],
    blocks: [],
    logs: [],
    timestamp: new Date().toISOString(),
    prev_hash: "GENESIS",
    hash: "",
    hash_version: 2,
  };
  // Compute real hash using the same algorithm as the sink
  const { hash: _, hmac_signature, ...rest } = entry;
  const keys = Object.keys(rest).sort();
  const payload = JSON.stringify(rest, keys);
  entry.hash = createHash("sha256").update(payload).digest("hex");
  return entry;
}

// ─── Write and read back ────────────────────────────────────────────

describe("ImmutableAuditSink", () => {
  it("stores an entry and retrieves it by hash", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("e1");
    await sink.append(entry);

    const retrieved = await sink.get(entry.hash);
    expect(retrieved).not.toBeNull();
    expect(retrieved!.entry_id).toBe("e1");
    expect(retrieved!.hash).toBe(entry.hash);
  });

  it("retrieved entry matches original exactly", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("e2");
    await sink.append(entry);

    const retrieved = await sink.get(entry.hash);
    expect(retrieved).toEqual(entry);
  });

  // ─── Write-once enforcement ──────────────────────────────────────

  it("appending the same entry twice is idempotent", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("e3");
    await sink.append(entry);
    // Should not throw
    await sink.append(entry);

    const retrieved = await sink.get(entry.hash);
    expect(retrieved).toEqual(entry);
  });

  it("throws ImmutabilityViolationError for different entry with same hash", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("e4");
    await sink.append(entry);

    // Create a different entry but force the same hash
    const imposter = { ...entry, entry_id: "imposter" };
    // imposter has the same hash but different content
    await expect(sink.append(imposter)).rejects.toThrow(ImmutabilityViolationError);
  });

  // ─── Content verification on read ────────────────────────────────

  it("get() succeeds for valid entries", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("e5");
    await sink.append(entry);

    const result = await sink.get(entry.hash);
    expect(result).toEqual(entry);
  });

  it("get() throws when file content is tampered", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("e6");
    await sink.append(entry);

    // Tamper with the stored file
    const hash = entry.hash;
    const filePath = path.join(tmpDir, hash.slice(0, 2), hash.slice(2, 4), `${hash}.json`);
    const stored = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    stored.allowed = false; // tamper
    fs.writeFileSync(filePath, JSON.stringify(stored, null, 2));

    await expect(sink.get(entry.hash)).rejects.toThrow("Tamper detected");
  });

  it("get() with verifyOnRead: false skips verification", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir, verifyOnRead: false });
    const entry = makeEntry("e7");
    await sink.append(entry);

    // Tamper with the stored file
    const hash = entry.hash;
    const filePath = path.join(tmpDir, hash.slice(0, 2), hash.slice(2, 4), `${hash}.json`);
    const stored = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    stored.allowed = false; // tamper
    fs.writeFileSync(filePath, JSON.stringify(stored, null, 2));

    // Should NOT throw — verification is disabled
    const result = await sink.get(entry.hash);
    expect(result).not.toBeNull();
    expect(result!.allowed).toBe(false);
  });

  // ─── has() check ─────────────────────────────────────────────────

  it("has() returns true for stored entries", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("e8");
    await sink.append(entry);

    expect(await sink.has(entry.hash)).toBe(true);
  });

  it("has() returns false for unknown hashes", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    expect(await sink.has("0000000000000000000000000000000000000000000000000000000000000000")).toBe(false);
  });

  // ─── Integrity verification ──────────────────────────────────────

  it("verifyIntegrity() returns valid for clean store", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const e1 = makeEntry("i1");
    const e2 = makeEntry("i2");
    await sink.append(e1);
    await sink.append(e2);

    const report = await sink.verifyIntegrity();
    expect(report.valid).toBe(true);
    expect(report.entriesChecked).toBe(2);
    expect(report.corruptEntries).toEqual([]);
  });

  it("verifyIntegrity() detects tampered entries", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("i3");
    await sink.append(entry);

    // Tamper with the stored file
    const hash = entry.hash;
    const filePath = path.join(tmpDir, hash.slice(0, 2), hash.slice(2, 4), `${hash}.json`);
    const stored = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    stored.allowed = false;
    fs.writeFileSync(filePath, JSON.stringify(stored, null, 2));

    const report = await sink.verifyIntegrity();
    expect(report.valid).toBe(false);
    expect(report.corruptEntries).toContain(hash);
  });

  it("verifyIntegrity() detects missing files", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("i4");
    await sink.append(entry);

    // Delete the stored file
    const hash = entry.hash;
    const filePath = path.join(tmpDir, hash.slice(0, 2), hash.slice(2, 4), `${hash}.json`);
    fs.unlinkSync(filePath);

    const report = await sink.verifyIntegrity();
    expect(report.valid).toBe(false);
    expect(report.corruptEntries).toContain(hash);
  });

  // ─── Index file ──────────────────────────────────────────────────

  it("index file has correct line count", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    await sink.append(makeEntry("idx1"));
    await sink.append(makeEntry("idx2"));
    await sink.append(makeEntry("idx3"));

    const indexPath = path.join(tmpDir, "_index.jsonl");
    const lines = fs.readFileSync(indexPath, "utf-8").trim().split("\n").filter(Boolean);
    expect(lines.length).toBe(3);
  });

  it("index entries contain entry_id, hash, and timestamp", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("idx4");
    await sink.append(entry);

    const indexPath = path.join(tmpDir, "_index.jsonl");
    const line = JSON.parse(fs.readFileSync(indexPath, "utf-8").trim());
    expect(line.entry_id).toBe(entry.entry_id);
    expect(line.hash).toBe(entry.hash);
    expect(line.timestamp).toBe(entry.timestamp);
  });

  // ─── Stats ───────────────────────────────────────────────────────

  it("getStats() returns correct entry count", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    await sink.append(makeEntry("s1"));
    await sink.append(makeEntry("s2"));

    const stats = await sink.getStats();
    expect(stats.entryCount).toBe(2);
  });

  it("getStats() returns valid disk bytes", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    await sink.append(makeEntry("s3"));

    const stats = await sink.getStats();
    expect(stats.diskBytes).toBeGreaterThan(0);
  });

  it("getStats() tracks oldest/newest timestamps", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });

    const e1 = makeEntry("s4");
    e1.timestamp = "2024-01-01T00:00:00.000Z";
    // Recompute hash after changing timestamp
    {
      const { hash: _, hmac_signature, ...rest } = e1;
      const keys = Object.keys(rest).sort();
      e1.hash = createHash("sha256").update(JSON.stringify(rest, keys)).digest("hex");
    }

    const e2 = makeEntry("s5");
    e2.timestamp = "2024-12-31T23:59:59.000Z";
    // Recompute hash after changing timestamp
    {
      const { hash: _, hmac_signature, ...rest } = e2;
      const keys = Object.keys(rest).sort();
      e2.hash = createHash("sha256").update(JSON.stringify(rest, keys)).digest("hex");
    }

    await sink.append(e1);
    await sink.append(e2);

    const stats = await sink.getStats();
    expect(stats.oldestEntry).toBe("2024-01-01T00:00:00.000Z");
    expect(stats.newestEntry).toBe("2024-12-31T23:59:59.000Z");
  });

  it("empty store returns count 0", async () => {
    const sink = new ImmutableAuditSink({ baseDir: tmpDir });
    const stats = await sink.getStats();
    expect(stats.entryCount).toBe(0);
    expect(stats.diskBytes).toBe(0);
  });

  // ─── Integration with AuditSink interface ────────────────────────

  it("ImmutableAuditSink implements AuditSink interface", async () => {
    const sink: AuditSink = new ImmutableAuditSink({ baseDir: tmpDir });
    const entry = makeEntry("iface1");

    // Should work through the AuditSink interface
    await sink.append(entry);

    // Verify via the concrete type
    const concrete = sink as ImmutableAuditSink;
    const retrieved = await concrete.get(entry.hash);
    expect(retrieved).toEqual(entry);
  });
});
