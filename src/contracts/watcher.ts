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
  /** Which contract each file last provided, so a changed or deleted file retires it. */
  private provided = new Map<string, { name: string; version: string }>();

  onReload?: (contract: TrustContract) => void;
  onError?: (err: Error, file: string) => void;

  constructor(gov: GodClause, opts: WatcherOptions) {
    this.gov = gov;
    this.dir = opts.dir;
    this.extensions = opts.extensions ?? [".yaml", ".yml", ".json"];
  }

  /** Start watching the directory for changes. */
  start(): void {
    if (this.fsWatcher || !existsSync(this.dir)) return;

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

  /** Reload all contract files from the directory and retire contracts whose files are gone. */
  reloadAll(): void {
    const files = existsSync(this.dir)
      ? readdirSync(this.dir).filter((f) => this.extensions.some((ext) => f.endsWith(ext)))
      : [];
    for (const file of files) {
      this.reloadFile(file);
    }
    for (const file of [...this.provided.keys()]) {
      if (!files.includes(file)) this.retire(file);
    }
  }

  /** Reload one file; a file that is gone retires the contract it provided. */
  reloadFile(filename: string): void {
    const path = join(this.dir, filename);
    if (!existsSync(path)) return this.retire(filename);

    try {
      const source = readFileSync(path, "utf-8");
      const contract = parseContract(source);
      const { name, version } = contract.metadata;
      const previous = this.provided.get(filename);
      this.gov.loadContract(contract);
      this.provided.set(filename, { name, version });
      if (previous && (previous.name !== name || previous.version !== version)) this.release(previous);
      this.onReload?.(contract);
    } catch (err: any) {
      if (err?.code === "ENOENT") return this.retire(filename);
      this.onError?.(err, filename);
    }
  }

  private retire(filename: string): void {
    const previous = this.provided.get(filename);
    if (!previous) return;
    this.provided.delete(filename);
    try {
      this.release(previous);
    } catch (err: any) {
      this.onError?.(err, filename);
    }
  }

  // A file stopped providing this contract. If another watched file (e.g. after a rename) still provides it,
  // re-read that file so its content is what the engine enforces; otherwise deactivate it.
  // shortcut: the watched directory is taken to own every name@version it provides; a contract also loaded
  // from another source is deactivated with it, so give other sources distinct names or versions.
  private release(c: { name: string; version: string }): void {
    for (const [file, p] of this.provided) {
      if (p.name === c.name && p.version === c.version) return this.reloadFile(file);
    }
    this.gov.deactivateContract(c.name, c.version);
  }
}
