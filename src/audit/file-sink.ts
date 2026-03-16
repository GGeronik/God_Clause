import { appendFileSync, renameSync, statSync, existsSync, unlinkSync } from "fs";
import { AuditSink } from "./audit-log";
import { AuditEntry } from "../types";

export interface FileSinkOptions {
  /** Path to the JSONL audit file. */
  path: string;
  /** Max file size in bytes before rotation. Default: 10MB. */
  maxSize?: number;
  /** Max number of rotated files to keep. Default: 5. */
  maxFiles?: number;
}

/**
 * Append-only JSONL file audit sink with log rotation.
 *
 * Each audit entry is written as a single JSON line. When the file
 * exceeds `maxSize`, it's rotated (audit.jsonl → audit.jsonl.1, etc.)
 * and old rotated files beyond `maxFiles` are deleted.
 */
export class FileAuditSink implements AuditSink {
  private path: string;
  private maxSize: number;
  private maxFiles: number;

  constructor(opts: FileSinkOptions) {
    this.path = opts.path;
    this.maxSize = opts.maxSize ?? 10 * 1024 * 1024;
    this.maxFiles = opts.maxFiles ?? 5;
  }

  append(entry: AuditEntry): void {
    this.rotateIfNeeded();
    appendFileSync(this.path, JSON.stringify(entry) + "\n", "utf-8");
  }

  private rotateIfNeeded(): void {
    if (!existsSync(this.path)) return;

    try {
      const stats = statSync(this.path);
      if (stats.size < this.maxSize) return;
    } catch {
      return;
    }

    // Shift existing rotated files up by one
    for (let i = this.maxFiles; i >= 1; i--) {
      const from = i === 1 ? this.path : `${this.path}.${i - 1}`;
      const to = `${this.path}.${i}`;
      if (existsSync(from)) {
        if (i === this.maxFiles) {
          // Delete the oldest file
          try { unlinkSync(to); } catch { /* ignore */ }
        }
        try { renameSync(from, to); } catch { /* ignore */ }
      }
    }
  }
}
