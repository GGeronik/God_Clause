import { TrustContract } from "../types";

interface RegistryEntry {
  contract: TrustContract;
  active: boolean;
}

/**
 * Contract registry supporting multiple versions of named contracts.
 * Each contract is identified by (name, version) and can be independently
 * activated or deactivated.
 */
export class ContractRegistry {
  private store = new Map<string, Map<string, RegistryEntry>>();

  private key(name: string): string {
    return name;
  }

  /** Register a contract, optionally activating it immediately. */
  register(contract: TrustContract, opts: { activate?: boolean } = {}): void {
    const name = contract.metadata.name;
    const version = contract.metadata.version;
    let versions = this.store.get(name);
    if (!versions) {
      versions = new Map();
      this.store.set(name, versions);
    }
    versions.set(version, {
      contract,
      active: opts.activate !== false, // default true
    });
  }

  /** Activate a specific version. */
  activate(name: string, version: string): void {
    const entry = this.getEntry(name, version);
    if (!entry) throw new Error(`Contract "${name}" version "${version}" not found`);
    entry.active = true;
  }

  /** Deactivate a specific version. */
  deactivate(name: string, version: string): void {
    const entry = this.getEntry(name, version);
    if (!entry) throw new Error(`Contract "${name}" version "${version}" not found`);
    entry.active = false;
  }

  /** Get the active contract for a given name (first active version). */
  getActive(name: string): TrustContract | undefined {
    const versions = this.store.get(name);
    if (!versions) return undefined;
    for (const entry of versions.values()) {
      if (entry.active) return entry.contract;
    }
    return undefined;
  }

  /** Get all active contracts across all names. */
  getAllActive(): TrustContract[] {
    const result: TrustContract[] = [];
    for (const versions of this.store.values()) {
      for (const entry of versions.values()) {
        if (entry.active) result.push(entry.contract);
      }
    }
    return result;
  }

  /** Get a specific version regardless of active state. */
  getVersion(name: string, version: string): TrustContract | undefined {
    return this.getEntry(name, version)?.contract;
  }

  /** List all registered contracts with their versions and active status. */
  list(): Array<{ name: string; versions: string[]; activeVersion: string | null }> {
    const result: Array<{ name: string; versions: string[]; activeVersion: string | null }> = [];
    for (const [name, versions] of this.store) {
      let activeVersion: string | null = null;
      const versionList: string[] = [];
      for (const [ver, entry] of versions) {
        versionList.push(ver);
        if (entry.active && !activeVersion) activeVersion = ver;
      }
      result.push({ name, versions: versionList, activeVersion });
    }
    return result;
  }

  /** Remove all registered contracts. */
  clear(): void {
    this.store.clear();
  }

  private getEntry(name: string, version: string): RegistryEntry | undefined {
    return this.store.get(name)?.get(version);
  }
}
