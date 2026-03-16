import { describe, it, expect, afterEach } from "vitest";
import { readFileSync, existsSync, unlinkSync, writeFileSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import { FileAuditSink, AuditEntry } from "../src";

function tmpPath(name: string): string {
  return join(tmpdir(), `god-clause-test-${name}-${Date.now()}.jsonl`);
}

function cleanup(...paths: string[]) {
  for (const p of paths) {
    for (const suffix of ["", ".1", ".2", ".3", ".4", ".5"]) {
      try { unlinkSync(p + suffix); } catch { /* ignore */ }
    }
  }
}

function makeEntry(id: string): AuditEntry {
  return {
    entry_id: id,
    decision_id: `dec-${id}`,
    contract_name: "test",
    contract_version: "1.0.0",
    action: "generate",
    caller: { user_id: "u1", session_id: "s1", roles: [] },
    allowed: true,
    rule_results: [],
    warnings: [],
    blocks: [],
    logs: [],
    timestamp: new Date().toISOString(),
    prev_hash: "GENESIS",
    hash: "abc123",
    hash_version: 2,
  };
}

describe("FileAuditSink", () => {
  const paths: string[] = [];

  afterEach(() => {
    cleanup(...paths);
  });

  it("creates a JSONL file with entries", () => {
    const path = tmpPath("basic");
    paths.push(path);
    const sink = new FileAuditSink({ path });

    sink.append(makeEntry("1"));
    sink.append(makeEntry("2"));

    const content = readFileSync(path, "utf-8");
    const lines = content.trim().split("\n");
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]).entry_id).toBe("1");
    expect(JSON.parse(lines[1]).entry_id).toBe("2");
  });

  it("rotates when file exceeds maxSize", () => {
    const path = tmpPath("rotate");
    paths.push(path);
    const sink = new FileAuditSink({ path, maxSize: 100, maxFiles: 3 });

    // Write enough entries to trigger rotation
    for (let i = 0; i < 5; i++) {
      sink.append(makeEntry(`entry-${i}`));
    }

    // At least one rotation should have occurred
    expect(existsSync(path)).toBe(true);
    // Rotated file should exist
    expect(existsSync(`${path}.1`)).toBe(true);
  });

  it("limits rotated files to maxFiles", () => {
    const path = tmpPath("max");
    paths.push(path);
    const sink = new FileAuditSink({ path, maxSize: 50, maxFiles: 2 });

    for (let i = 0; i < 20; i++) {
      sink.append(makeEntry(`e-${i}`));
    }

    // Should not have more than maxFiles rotated files
    expect(existsSync(`${path}.3`)).toBe(false);
  });
});
