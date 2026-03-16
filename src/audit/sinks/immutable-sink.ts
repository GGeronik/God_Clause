import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import { AuditEntry, ImmutableSinkOptions, IntegrityReport, ImmutableStoreStats } from "../../types";
import { AuditSink } from "../audit-log";

export class ImmutabilityViolationError extends Error {
  constructor(hash: string) {
    super(`Immutability violation: entry with hash ${hash} already exists with different content`);
    this.name = "ImmutabilityViolationError";
  }
}

export class ImmutableAuditSink implements AuditSink {
  private baseDir: string;
  private verifyOnRead: boolean;
  private initialized = false;

  constructor(opts: ImmutableSinkOptions) {
    this.baseDir = opts.baseDir;
    this.verifyOnRead = opts.verifyOnRead ?? true;
  }

  // Implementation of AuditSink interface
  async append(entry: AuditEntry): Promise<void> {
    this.ensureInitialized();
    const hash = entry.hash;
    const filePath = this.hashToPath(hash);
    const dir = path.dirname(filePath);

    // Create directory structure
    fs.mkdirSync(dir, { recursive: true });

    // Write-once enforcement
    if (fs.existsSync(filePath)) {
      const existing = JSON.parse(fs.readFileSync(filePath, "utf-8"));
      if (existing.hash === entry.hash && existing.entry_id === entry.entry_id) {
        return; // Idempotent — same content
      }
      throw new ImmutabilityViolationError(hash);
    }

    // Write entry
    fs.writeFileSync(filePath, JSON.stringify(entry, null, 2));

    // Append to index
    const indexLine = JSON.stringify({ entry_id: entry.entry_id, hash: entry.hash, timestamp: entry.timestamp }) + "\n";
    fs.appendFileSync(path.join(this.baseDir, "_index.jsonl"), indexLine);

    // Update manifest
    this.updateManifest(entry);
  }

  // Read an entry by its hash
  async get(entryHash: string): Promise<AuditEntry | null> {
    this.ensureInitialized();
    const filePath = this.hashToPath(entryHash);

    if (!fs.existsSync(filePath)) return null;

    const content = fs.readFileSync(filePath, "utf-8");
    const entry = JSON.parse(content) as AuditEntry;

    // Verify on read
    if (this.verifyOnRead) {
      const computedHash = this.computeEntryHash(entry);
      if (computedHash !== entryHash) {
        throw new Error(`Tamper detected: entry hash mismatch for ${entryHash}`);
      }
    }

    return entry;
  }

  // Check if an entry exists
  async has(entryHash: string): Promise<boolean> {
    this.ensureInitialized();
    return fs.existsSync(this.hashToPath(entryHash));
  }

  // Verify integrity of all stored entries
  async verifyIntegrity(): Promise<IntegrityReport> {
    this.ensureInitialized();
    const corruptEntries: string[] = [];
    let entriesChecked = 0;

    // Read index to get all entry hashes
    const indexPath = path.join(this.baseDir, "_index.jsonl");
    if (!fs.existsSync(indexPath)) {
      return { valid: true, entriesChecked: 0, corruptEntries: [], timestamp: new Date().toISOString() };
    }

    const lines = fs.readFileSync(indexPath, "utf-8").trim().split("\n").filter(Boolean);

    for (const line of lines) {
      const { hash } = JSON.parse(line);
      entriesChecked++;

      const filePath = this.hashToPath(hash);
      if (!fs.existsSync(filePath)) {
        corruptEntries.push(hash);
        continue;
      }

      try {
        const content = fs.readFileSync(filePath, "utf-8");
        const entry = JSON.parse(content) as AuditEntry;
        const computedHash = this.computeEntryHash(entry);
        if (computedHash !== hash) {
          corruptEntries.push(hash);
        }
      } catch {
        corruptEntries.push(hash);
      }
    }

    return {
      valid: corruptEntries.length === 0,
      entriesChecked,
      corruptEntries,
      timestamp: new Date().toISOString(),
    };
  }

  // Get store statistics
  async getStats(): Promise<ImmutableStoreStats> {
    this.ensureInitialized();
    const indexPath = path.join(this.baseDir, "_index.jsonl");

    if (!fs.existsSync(indexPath)) {
      return { entryCount: 0, diskBytes: 0 };
    }

    const lines = fs.readFileSync(indexPath, "utf-8").trim().split("\n").filter(Boolean);
    let diskBytes = 0;
    let oldestEntry: string | undefined;
    let newestEntry: string | undefined;

    for (const line of lines) {
      const { hash, timestamp } = JSON.parse(line);
      const filePath = this.hashToPath(hash);
      if (fs.existsSync(filePath)) {
        diskBytes += fs.statSync(filePath).size;
      }
      if (!oldestEntry || timestamp < oldestEntry) oldestEntry = timestamp;
      if (!newestEntry || timestamp > newestEntry) newestEntry = timestamp;
    }

    return {
      entryCount: lines.length,
      diskBytes,
      oldestEntry,
      newestEntry,
    };
  }

  // ─── Private helpers ──────────────────────────────────────────────

  private ensureInitialized(): void {
    if (this.initialized) return;
    fs.mkdirSync(this.baseDir, { recursive: true });
    this.initialized = true;
  }

  private hashToPath(hash: string): string {
    // 2-level shard: {baseDir}/{hash[0:2]}/{hash[2:4]}/{hash}.json
    return path.join(this.baseDir, hash.slice(0, 2), hash.slice(2, 4), `${hash}.json`);
  }

  private computeEntryHash(entry: AuditEntry): string {
    const { hash, hmac_signature, ...rest } = entry;
    const keys = Object.keys(rest).sort();
    const payload = JSON.stringify(rest, keys);
    return createHash("sha256").update(payload).digest("hex");
  }

  private updateManifest(entry: AuditEntry): void {
    const manifestPath = path.join(this.baseDir, "_manifest.json");
    let manifest: Record<string, unknown> = {};

    if (fs.existsSync(manifestPath)) {
      manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
    }

    manifest.lastUpdated = new Date().toISOString();
    manifest.entryCount = ((manifest.entryCount as number) || 0) + 1;
    manifest.lastEntryHash = entry.hash;

    if (!manifest.createdAt) {
      manifest.createdAt = new Date().toISOString();
    }

    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));
  }
}
