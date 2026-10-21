import {
  appendFileSync,
  closeSync,
  existsSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  statSync,
  unlinkSync,
} from "fs";
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
  private tailChecked = false;

  constructor(opts: FileSinkOptions) {
    this.path = opts.path;
    this.maxSize = opts.maxSize ?? 10 * 1024 * 1024;
    this.maxFiles = opts.maxFiles ?? 5;
  }

  append(entry: AuditEntry): void {
    this.rotateIfNeeded();
    appendFileSync(this.path, (this.tornTail() ? "\n" : "") + JSON.stringify(entry) + "\n", "utf-8");
  }

  // A crash mid-append leaves an unterminated last line; without a newline the next entry would fuse onto it.
  private tornTail(): boolean {
    if (this.tailChecked) return false;
    this.tailChecked = true;
    if (!existsSync(this.path)) return false;
    const size = statSync(this.path).size;
    if (size === 0) return false;
    const fd = openSync(this.path, "r");
    const last = Buffer.alloc(1);
    try {
      readSync(fd, last, 0, 1, size - 1);
    } finally {
      closeSync(fd);
    }
    return last[0] !== 0x0a;
  }

  /** Hash of the last intact entry in an existing file, for `headHash` when resuming a chain. */
  static lastHash(path: string): string | undefined {
    if (!existsSync(path)) return undefined;
    // shortcut: reads the whole file, bounded by maxSize; stream the tail if that limit is raised far
    const lines = readFileSync(path, "utf-8").trim().split("\n");
    for (let i = lines.length - 1; i >= 0; i--) {
      try {
        return (JSON.parse(lines[i]) as AuditEntry).hash;
      } catch {
        // torn write from a crash mid-append: resume from the entry before it
      }
    }
    return undefined;
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
          try {
            unlinkSync(to);
          } catch {
            /* ignore */
          }
        }
        try {
          renameSync(from, to);
        } catch {
          /* ignore */
        }
      }
    }
  }
}
