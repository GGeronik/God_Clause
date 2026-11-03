import { randomUUID, createSign, createVerify } from "crypto";
import { readFileSync } from "fs";
import type { TrustContract } from "../types";
import type { DSSEEnvelope, SigningOptions, VerifyOptions } from "../crypto/dsse";
import { paeEncode, contractFingerprint } from "../crypto/dsse";
import { ContractParseError, validateContract } from "./parser";

// ─── Types ───────────────────────────────────────────────────────────

export interface PolicyBundle {
  format_version: string;
  created_at: string;
  bundle_id: string;
  contracts: TrustContract[];
  metadata: {
    author?: string;
    description?: string;
    contract_fingerprints: string[];
  };
}

export interface SignedBundle {
  envelope: DSSEEnvelope;
}

export interface BundleWatcherOptions {
  /** URL (http/https) or local file path to a signed bundle JSON. */
  source: string;
  /** Polling interval in milliseconds. Default: 30000 */
  pollIntervalMs?: number;
  /** PEM-encoded public key for signature verification. */
  publicKey: string;
  /** Reload callback — called with the full contracts array on each new bundle. */
  onReload?: (contracts: TrustContract[]) => void;
  /** Error callback — called when polling or verification fails. */
  onError?: (err: Error) => void;
  /** Signature algorithm. Default: "sha256" */
  algorithm?: string;
}

// ─── Constants ───────────────────────────────────────────────────────

const BUNDLE_PAYLOAD_TYPE = "application/vnd.godclause.bundle+json";

// ─── Functions ───────────────────────────────────────────────────────

/**
 * Pack an array of trust contracts into a PolicyBundle.
 */
export function packBundle(contracts: TrustContract[], opts?: { author?: string; description?: string }): PolicyBundle {
  return {
    format_version: "1.0",
    created_at: new Date().toISOString(),
    bundle_id: randomUUID(),
    contracts,
    metadata: {
      author: opts?.author,
      description: opts?.description,
      contract_fingerprints: contracts.map((c) => contractFingerprint(c)),
    },
  };
}

/**
 * Sign a PolicyBundle using DSSE envelope format.
 */
export function signBundle(bundle: PolicyBundle, opts: SigningOptions): SignedBundle {
  const payloadB64 = Buffer.from(JSON.stringify(bundle)).toString("base64");
  const pae = paeEncode(BUNDLE_PAYLOAD_TYPE, payloadB64);

  const signer = createSign(opts.algorithm ?? "sha256");
  signer.update(pae);
  const signature = signer.sign(opts.privateKey, "base64");

  return {
    envelope: {
      payloadType: BUNDLE_PAYLOAD_TYPE,
      payload: payloadB64,
      signatures: [
        {
          keyid: opts.keyId,
          sig: signature,
        },
      ],
    },
  };
}

/**
 * Verify a signed bundle's DSSE envelope and validate every contract in it.
 * Returns { valid: true, bundle } on success, or { valid: false } when no signature
 * verifies. Throws ContractParseError when a verified payload is not a valid bundle.
 */
export function verifyBundle(signed: SignedBundle, opts: VerifyOptions): { valid: boolean; bundle?: PolicyBundle } {
  const { envelope } = signed;
  if (envelope.payloadType !== BUNDLE_PAYLOAD_TYPE) return { valid: false };

  for (const sig of envelope.signatures) {
    const pae = paeEncode(envelope.payloadType, envelope.payload);
    const verifier = createVerify(opts.algorithm ?? "sha256");
    verifier.update(pae);

    const valid = verifier.verify(opts.publicKey, sig.sig, "base64");
    if (valid) {
      const json = Buffer.from(envelope.payload, "base64").toString("utf-8");
      const bundle = JSON.parse(json) as PolicyBundle | null;
      if (!bundle || !Array.isArray(bundle.contracts)) {
        throw new ContractParseError("Signed payload is not a policy bundle", ["/contracts: must be an array"]);
      }
      bundle.contracts = bundle.contracts.map(validateContract);
      return { valid: true, bundle };
    }
  }

  return { valid: false };
}

/**
 * Verify and unpack a signed bundle, returning the contracts array.
 * Throws if signature verification fails.
 */
export function unpackBundle(signed: SignedBundle, opts: VerifyOptions): TrustContract[] {
  const result = verifyBundle(signed, opts);
  if (!result.valid || !result.bundle) {
    throw new Error("Bundle signature verification failed");
  }
  return result.bundle.contracts;
}

// ─── BundleWatcher ───────────────────────────────────────────────────

/**
 * Polls a signed bundle source (URL or local file); each new bundle replaces
 * the attached GodClause instance's contracts with the bundle's set.
 */
export class BundleWatcher {
  private timer: ReturnType<typeof setInterval> | null = null;
  private lastBundleId: string | null = null;
  private gov: { replaceContracts(contracts: TrustContract[]): void } | null = null;

  constructor(private opts: BundleWatcherOptions) {}

  /** Attach a GodClause instance; each new bundle replaces its whole contract set, whatever else was loaded. */
  attach(gov: { replaceContracts(contracts: TrustContract[]): void }): void {
    this.gov = gov;
    this.lastBundleId = null; // so the next poll applies the current bundle to this instance
  }

  /** Start polling. Performs an immediate first poll. */
  start(): void {
    // Immediate first poll
    void this.poll();
    this.timer = setInterval(() => void this.poll(), this.opts.pollIntervalMs ?? 30000);
  }

  /** Stop polling. */
  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async poll(): Promise<void> {
    try {
      const raw = await this.fetchSource();
      const signed = JSON.parse(raw) as SignedBundle;

      const result = verifyBundle(signed, {
        publicKey: this.opts.publicKey,
        algorithm: this.opts.algorithm,
      });

      if (!result.valid || !result.bundle) {
        throw new Error("Bundle signature verification failed");
      }

      // Skip reload if bundle hasn't changed
      if (result.bundle.bundle_id === this.lastBundleId) {
        return;
      }

      this.lastBundleId = result.bundle.bundle_id;

      this.gov?.replaceContracts(result.bundle.contracts);

      this.opts.onReload?.(result.bundle.contracts);
    } catch (err: any) {
      this.opts.onError?.(err instanceof Error ? err : new Error(String(err)));
    }
  }

  private async fetchSource(): Promise<string> {
    const { source } = this.opts;
    if (source.startsWith("http://") || source.startsWith("https://")) {
      const res = await fetch(source);
      if (!res.ok) {
        throw new Error(`Failed to fetch bundle: ${res.status} ${res.statusText}`);
      }
      return res.text();
    }
    return readFileSync(source, "utf-8");
  }
}
