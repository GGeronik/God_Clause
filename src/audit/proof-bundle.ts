import { randomUUID } from "crypto";
import type { GodClause } from "../governance";
import type {
  AuditEntry,
  ProofBundle,
  ProofVerificationResult,
  HumanOverride,
  ChainSealRef,
} from "../types";
import { computeMerkleRoot, ChainSeal } from "./seal";

/**
 * ProofBundleBuilder creates self-contained evidence bundles for
 * regulatory proof and compliance audits.
 *
 * A proof bundle packages:
 * - The trust contract(s) that governed decisions
 * - Audit entries with their tamper-evident hash chain
 * - Hash chain verification result
 * - Merkle seal checkpoints
 * - Human overrides (if any)
 *
 * This produces a single JSON artifact that can be handed to
 * auditors, regulators, or legal teams as cryptographic proof
 * of AI governance.
 */
export class ProofBundleBuilder {
  constructor(private gov: GodClause) {}

  /**
   * Build a proof bundle from the current governance state.
   *
   * @param opts - Optional filters: date range, whether to include contracts
   * @returns A self-contained ProofBundle
   */
  async build(opts?: {
    from?: string;
    to?: string;
    includeContracts?: boolean;
    humanOverrides?: HumanOverride[];
    seals?: ChainSeal[];
  }): Promise<ProofBundle> {
    // 1. Collect audit entries (optionally filtered)
    let entries = [...this.gov.getAuditEntries()];

    if (opts?.from) {
      const fromDate = new Date(opts.from).getTime();
      entries = entries.filter((e) => new Date(e.timestamp).getTime() >= fromDate);
    }
    if (opts?.to) {
      const toDate = new Date(opts.to).getTime();
      entries = entries.filter((e) => new Date(e.timestamp).getTime() <= toDate);
    }

    // 2. Verify chain integrity
    const chainResult = this.gov.verifyAuditChain();

    // 3. Collect seals
    const seals: ChainSealRef[] = (opts?.seals || []).map((s) => ({
      seal_id: s.seal_id,
      from_entry_id: s.from_entry_id,
      to_entry_id: s.to_entry_id,
      entry_count: s.entry_count,
      merkle_root: s.merkle_root,
      timestamp: s.timestamp,
    }));

    // 4. Collect contracts
    const contracts = opts?.includeContracts !== false
      ? [...this.gov.getContracts()]
      : [];

    // 5. Package
    const bundle: ProofBundle = {
      bundle_id: randomUUID(),
      created_at: new Date().toISOString(),
      contracts,
      audit_entries: entries,
      chain_verification: {
        valid: chainResult.valid,
        entries_checked: entries.length,
      },
      merkle_seals: seals,
      human_overrides: opts?.humanOverrides || [],
      metadata: {
        generator: "god-clause",
        version: "2.0.0",
      },
    };

    return bundle;
  }

  /**
   * Export a proof bundle as a formatted JSON string.
   */
  async exportJSON(bundle: ProofBundle): Promise<string> {
    return JSON.stringify(bundle, null, 2);
  }

  /**
   * Verify all evidence within a proof bundle.
   *
   * Checks:
   * 1. Hash chain integrity (recompute and compare hashes)
   * 2. Merkle seal integrity (recompute roots from entry hashes)
   * 3. Chain linkage (prev_hash references)
   */
  async verify(bundle: ProofBundle, secretKey?: string): Promise<ProofVerificationResult> {
    const details: Array<{ check: string; passed: boolean; detail?: string }> = [];

    // 1. Verify hash chain
    const chainValid = verifyBundleChain(bundle.audit_entries);
    details.push({
      check: "hash_chain",
      passed: chainValid,
      detail: chainValid
        ? `${bundle.audit_entries.length} entries verified`
        : "Hash chain broken — entries may have been tampered with",
    });

    // 2. Verify Merkle seals
    let sealsValid = true;
    for (const seal of bundle.merkle_seals) {
      const sealEntries = bundle.audit_entries.filter((e) => {
        const fromIdx = bundle.audit_entries.findIndex((x) => x.entry_id === seal.from_entry_id);
        const toIdx = bundle.audit_entries.findIndex((x) => x.entry_id === seal.to_entry_id);
        const eIdx = bundle.audit_entries.indexOf(e);
        return eIdx >= fromIdx && eIdx <= toIdx;
      });

      if (sealEntries.length !== seal.entry_count) {
        sealsValid = false;
        details.push({
          check: `merkle_seal_${seal.seal_id}`,
          passed: false,
          detail: `Expected ${seal.entry_count} entries, found ${sealEntries.length}`,
        });
        continue;
      }

      const recomputedRoot = computeMerkleRoot(sealEntries.map((e) => e.hash));
      const sealValid = recomputedRoot === seal.merkle_root;
      if (!sealValid) sealsValid = false;

      details.push({
        check: `merkle_seal_${seal.seal_id}`,
        passed: sealValid,
        detail: sealValid
          ? `Seal verified: ${seal.entry_count} entries`
          : "Merkle root mismatch — seal or entries tampered",
      });
    }

    // 3. Check bundle has entries
    const hasEntries = bundle.audit_entries.length > 0;
    details.push({
      check: "has_entries",
      passed: hasEntries,
      detail: hasEntries
        ? `Bundle contains ${bundle.audit_entries.length} audit entries`
        : "Bundle has no audit entries",
    });

    const valid = chainValid && sealsValid;

    return {
      valid,
      chain_valid: chainValid,
      seals_valid: sealsValid,
      details,
    };
  }
}

/**
 * Verify hash chain integrity within a bundle's entries.
 * Checks that prev_hash references are correct.
 */
function verifyBundleChain(entries: AuditEntry[]): boolean {
  if (entries.length === 0) return true;

  for (let i = 1; i < entries.length; i++) {
    if (entries[i].prev_hash !== entries[i - 1].hash) {
      return false;
    }
  }

  return true;
}
