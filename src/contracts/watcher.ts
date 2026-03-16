import { watch, readFileSync, readdirSync, existsSync, FSWatcher } from "fs";
import { join } from "path";
import type { TrustContract } from "../types";
import type { GodClause } from "../governance";
import { parseContract, ContractParseError } from "./parser";

export interface WatcherOptions {
  /** Directory to watch for contract files. */
  dir: string;
  /** File extensions to watch. Default: [".yaml", ".yml", ".json"] */
  extensions?: string[];
}

/**
 * Watches a directory for trust contract changes and auto-reloads them.
 *
 * Enables zero-downtime policy updates — edit a contract YAML file and
 * it's automatically reloaded without restarting the server.
 *
 * ```ts
 * const watcher = new ContractWatcher(gov, { dir: "./contracts" });
 * watcher.onReload = (contract) => console.log(`Reloaded: ${contract.metadata.name}`);
 * watcher.start();
 * ```
 */
export class ContractWatcher {
  private gov: GodClause;
  private dir: string;
  private extensions: string[];
  private fsWatcher: FSWatcher | null = null;
  private debounceTimers = new Map<string, ReturnType<typeof setTimeout>>();

  onReload?: (contract: TrustContract) => void;
  onError?: (err: Error, file: string) => void;

  constructor(gov: GodClause, opts: WatcherOptions) {
    this.gov = gov;
    this.dir = opts.dir;
    this.extensions = opts.extensions ?? [".yaml", ".yml", ".json"];
  }

  /** Start watching the directory for changes. */
  start(): void {
    if (!existsSync(this.dir)) return;

    this.fsWatcher = watch(this.dir, { persistent: false }, (_event, filename) => {
      if (!filename) return;
      if (!this.extensions.some((ext) => filename.endsWith(ext))) return;

      // Debounce rapid changes (editors often write multiple times)
      const existing = this.debounceTimers.get(filename);
      if (existing) clearTimeout(existing);

      this.debounceTimers.set(
        filename,
        setTimeout(() => {
          this.debounceTimers.delete(filename);
          this.reloadFile(filename);
        }, 200),
      );
    });
  }

  /** Stop watching. */
  stop(): void {
    if (this.fsWatcher) {
      this.fsWatcher.close();
      this.fsWatcher = null;
    }
    for (const timer of this.debounceTimers.values()) {
      clearTimeout(timer);
    }
    this.debounceTimers.clear();
  }

  /** Reload all contract files from the directory. */
  reloadAll(): void {
    if (!existsSync(this.dir)) return;
    const files = readdirSync(this.dir).filter((f) =>
      this.extensions.some((ext) => f.endsWith(ext)),
    );
    for (const file of files) {
      this.reloadFile(file);
    }
  }

  private reloadFile(filename: string): void {
    const path = join(this.dir, filename);
    if (!existsSync(path)) return;

    try {
      const source = readFileSync(path, "utf-8");
      const contract = parseContract(source);
      this.gov.loadContract(contract);
      this.onReload?.(contract);
    } catch (err: any) {
      this.onError?.(err, filename);
    }
  }
}
