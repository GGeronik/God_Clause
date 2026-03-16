import {
  createHash,
  generateKeyPairSync,
  sign,
  verify,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  KeyObject,
} from "crypto";
import { execFile } from "child_process";
import { TrustQuote, TrustAnchorInfo } from "../types";

// ─── TrustAnchor Interface ──────────────────────────────────────────

/**
 * Pluggable trust anchor interface for hardware or software-backed
 * cryptographic operations: signing, attestation quotes, and data sealing.
 */
export interface TrustAnchor {
  /** Trust anchor type identifier (e.g. "software", "tpm", "sgx"). */
  readonly type: string;

  /** Initialize the trust anchor (generate or load keys). */
  initialize(): Promise<void>;

  /** Check whether this trust anchor is available on the current platform. */
  isAvailable(): Promise<boolean>;

  /** Get the public key (hex-encoded). */
  getPublicKey(): Promise<string>;

  /** Sign arbitrary data. Returns the signature as a Buffer. */
  sign(data: Buffer): Promise<Buffer>;

  /** Verify a signature against data and a public key. */
  verify(data: Buffer, signature: Buffer, publicKey?: string): Promise<boolean>;

  /** Generate an attestation quote over a nonce. */
  quote(nonce: Buffer): Promise<TrustQuote>;

  /** Encrypt data bound to this platform (sealed storage). */
  sealData(data: Buffer): Promise<Buffer>;

  /** Decrypt previously sealed data. */
  unsealData(sealed: Buffer): Promise<Buffer>;

  /** Get information about this anchor's capabilities. */
  getInfo(): TrustAnchorInfo;
}

// ─── Software Trust Anchor ──────────────────────────────────────────

/**
 * Software-based trust anchor using Ed25519 for signing and AES-256-GCM
 * for data sealing. Always available — no hardware dependencies.
 */
export class SoftwareTrustAnchor implements TrustAnchor {
  readonly type = "software";
  private publicKey: KeyObject | null = null;
  private privateKey: KeyObject | null = null;
  private sealingKey: Buffer | null = null;
  private initialized = false;

  async initialize(): Promise<void> {
    const keyPair = generateKeyPairSync("ed25519");
    this.publicKey = keyPair.publicKey;
    this.privateKey = keyPair.privateKey;
    this.sealingKey = randomBytes(32); // AES-256 key
    this.initialized = true;
  }

  async isAvailable(): Promise<boolean> {
    return true; // Software anchor is always available
  }

  async getPublicKey(): Promise<string> {
    this.ensureInitialized();
    return this.publicKey!.export({ type: "spki", format: "der" }).toString("hex");
  }

  async sign(data: Buffer): Promise<Buffer> {
    this.ensureInitialized();
    return sign(null, data, this.privateKey!);
  }

  async verify(data: Buffer, signature: Buffer, publicKeyHex?: string): Promise<boolean> {
    this.ensureInitialized();
    let pubKey: KeyObject;
    if (publicKeyHex) {
      pubKey = createPublicKeyFromHex(publicKeyHex);
    } else {
      pubKey = this.publicKey!;
    }
    return verify(null, data, pubKey, signature);
  }

  async quote(nonce: Buffer): Promise<TrustQuote> {
    this.ensureInitialized();
    const timestamp = new Date().toISOString();

    // Software measurements: hashes of runtime state
    const measurements: Record<string, string> = {
      node_version: createHash("sha256").update(process.version).digest("hex"),
      platform: createHash("sha256").update(`${process.platform}-${process.arch}`).digest("hex"),
      uptime: createHash("sha256")
        .update(String(Math.floor(process.uptime())))
        .digest("hex"),
    };

    // Build quote payload and sign it
    const payload = Buffer.from(
      JSON.stringify({
        nonce: nonce.toString("hex"),
        measurements,
        timestamp,
      }),
    );

    const signature = await this.sign(payload);

    return {
      anchorType: this.type,
      publicKey: await this.getPublicKey(),
      nonce: nonce.toString("hex"),
      measurements,
      signature: signature.toString("hex"),
      timestamp,
    };
  }

  async sealData(data: Buffer): Promise<Buffer> {
    this.ensureInitialized();
    const iv = randomBytes(12); // 96-bit IV for GCM
    const cipher = createCipheriv("aes-256-gcm", this.sealingKey!, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Format: [iv (12 bytes)][authTag (16 bytes)][encrypted data]
    return Buffer.concat([iv, authTag, encrypted]);
  }

  async unsealData(sealed: Buffer): Promise<Buffer> {
    this.ensureInitialized();
    if (sealed.length < 28) {
      throw new Error("Invalid sealed data: too short");
    }

    const iv = sealed.subarray(0, 12);
    const authTag = sealed.subarray(12, 28);
    const encrypted = sealed.subarray(28);

    const decipher = createDecipheriv("aes-256-gcm", this.sealingKey!, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  }

  getInfo(): TrustAnchorInfo {
    return {
      type: this.type,
      available: true,
      capabilities: ["sign", "verify", "quote", "seal", "unseal"],
    };
  }

  private ensureInitialized(): void {
    if (!this.initialized) {
      throw new Error("SoftwareTrustAnchor not initialized. Call initialize() first.");
    }
  }
}

// ─── TPM Trust Anchor ───────────────────────────────────────────────

/**
 * TPM 2.0 trust anchor that shells out to tpm2-tools CLI.
 * Falls back gracefully when tpm2-tools is not installed.
 */
export class TPMTrustAnchor implements TrustAnchor {
  readonly type = "tpm";
  private available: boolean | null = null;
  private fallback: SoftwareTrustAnchor | null = null;

  async initialize(): Promise<void> {
    const isAvail = await this.isAvailable();
    if (!isAvail) {
      this.fallback = new SoftwareTrustAnchor();
      await this.fallback.initialize();
    }
    // In a real implementation, would run:
    // tpm2_createprimary -C e -g sha256 -G ecc256
    // tpm2_create -C primary.ctx -g sha256 -G ecc256
  }

  async isAvailable(): Promise<boolean> {
    if (this.available !== null) return this.available;

    return new Promise<boolean>((resolve) => {
      execFile("tpm2_getcap", ["properties-fixed"], { timeout: 5000 }, (error) => {
        this.available = !error;
        resolve(!error);
      });
    });
  }

  async getPublicKey(): Promise<string> {
    if (this.fallback) return this.fallback.getPublicKey();
    // Real implementation: tpm2_readpublic -c key.ctx -o pub.pem
    throw new Error("TPM public key retrieval not implemented — use software fallback");
  }

  async sign(data: Buffer): Promise<Buffer> {
    if (this.fallback) return this.fallback.sign(data);
    // Real implementation: tpm2_sign -c key.ctx -g sha256 -o sig.bin data.bin
    throw new Error("TPM signing not implemented — use software fallback");
  }

  async verify(data: Buffer, signature: Buffer, publicKey?: string): Promise<boolean> {
    if (this.fallback) return this.fallback.verify(data, signature, publicKey);
    // Real implementation: tpm2_verifysignature
    throw new Error("TPM verification not implemented — use software fallback");
  }

  async quote(nonce: Buffer): Promise<TrustQuote> {
    if (this.fallback) {
      const q = await this.fallback.quote(nonce);
      q.anchorType = "tpm-fallback";
      return q;
    }
    // Real implementation: tpm2_quote -c ak.ctx -l sha256:0,1,2 -q nonce -o quote.bin
    throw new Error("TPM quote not implemented — use software fallback");
  }

  async sealData(data: Buffer): Promise<Buffer> {
    if (this.fallback) return this.fallback.sealData(data);
    throw new Error("TPM sealing not implemented — use software fallback");
  }

  async unsealData(sealed: Buffer): Promise<Buffer> {
    if (this.fallback) return this.fallback.unsealData(sealed);
    throw new Error("TPM unsealing not implemented — use software fallback");
  }

  getInfo(): TrustAnchorInfo {
    return {
      type: this.type,
      available: this.available ?? false,
      capabilities: this.available
        ? ["sign", "verify", "quote", "seal", "unseal", "pcr"]
        : ["sign", "verify", "quote", "seal", "unseal"], // via fallback
    };
  }
}

// ─── SGX Trust Anchor (Stub) ────────────────────────────────────────

/**
 * Intel SGX trust anchor — documented stub for future hardware integration.
 *
 * A real implementation would require:
 * - Intel SGX SDK (linux-sgx or Open Enclave SDK)
 * - SGX-capable CPU with SGX enabled in BIOS
 * - AESM service running for quoting/attestation
 * - Enclave binary (.so) compiled with sgx_edger8r
 *
 * Key operations would include:
 * - sgx_create_enclave() for initialization
 * - sgx_get_quote() for EPID/DCAP attestation
 * - sgx_seal_data() for enclave-bound encryption
 * - sgx_ra_init() for remote attestation
 */
export class SGXTrustAnchor implements TrustAnchor {
  readonly type = "sgx";

  async initialize(): Promise<void> {
    throw new NotImplementedError("SGX", "Intel SGX SDK and SGX-capable hardware");
  }

  async isAvailable(): Promise<boolean> {
    return false;
  }

  async getPublicKey(): Promise<string> {
    throw new NotImplementedError("SGX", "enclave identity key");
  }

  async sign(data: Buffer): Promise<Buffer> {
    throw new NotImplementedError("SGX", "enclave signing");
  }

  async verify(data: Buffer, signature: Buffer): Promise<boolean> {
    throw new NotImplementedError("SGX", "enclave verification");
  }

  async quote(nonce: Buffer): Promise<TrustQuote> {
    throw new NotImplementedError("SGX", "DCAP/EPID attestation");
  }

  async sealData(data: Buffer): Promise<Buffer> {
    throw new NotImplementedError("SGX", "sgx_seal_data");
  }

  async unsealData(sealed: Buffer): Promise<Buffer> {
    throw new NotImplementedError("SGX", "sgx_unseal_data");
  }

  getInfo(): TrustAnchorInfo {
    return { type: "sgx", available: false, capabilities: [] };
  }
}

// ─── Firecracker Trust Anchor (Stub) ────────────────────────────────

/**
 * Firecracker microVM trust anchor — documented stub for future integration.
 *
 * A real implementation would require:
 * - Firecracker VMM binary
 * - Linux with KVM support
 * - Firecracker API socket for VM management
 *
 * Key operations would include:
 * - VM snapshot for deterministic state attestation
 * - Guest-to-host attestation via vsock
 * - Rate-limited API calls for capability restriction
 * - Jailer for additional sandboxing
 */
export class FirecrackerTrustAnchor implements TrustAnchor {
  readonly type = "firecracker";

  async initialize(): Promise<void> {
    throw new NotImplementedError("Firecracker", "Firecracker VMM and KVM support");
  }

  async isAvailable(): Promise<boolean> {
    return false;
  }

  async getPublicKey(): Promise<string> {
    throw new NotImplementedError("Firecracker", "VM identity key");
  }

  async sign(data: Buffer): Promise<Buffer> {
    throw new NotImplementedError("Firecracker", "VM-bound signing");
  }

  async verify(data: Buffer, signature: Buffer): Promise<boolean> {
    throw new NotImplementedError("Firecracker", "VM-bound verification");
  }

  async quote(nonce: Buffer): Promise<TrustQuote> {
    throw new NotImplementedError("Firecracker", "VM snapshot attestation");
  }

  async sealData(data: Buffer): Promise<Buffer> {
    throw new NotImplementedError("Firecracker", "VM-bound sealing");
  }

  async unsealData(sealed: Buffer): Promise<Buffer> {
    throw new NotImplementedError("Firecracker", "VM-bound unsealing");
  }

  getInfo(): TrustAnchorInfo {
    return { type: "firecracker", available: false, capabilities: [] };
  }
}

// ─── Factory ────────────────────────────────────────────────────────

/**
 * Create a trust anchor using the first available backend from the
 * preference list. Defaults to ["tpm", "software"].
 */
export async function createTrustAnchor(preference: string[] = ["tpm", "software"]): Promise<TrustAnchor> {
  for (const pref of preference) {
    const anchor = createAnchorByType(pref);
    if (!anchor) continue;

    const available = await anchor.isAvailable();
    if (available) {
      await anchor.initialize();
      return anchor;
    }
  }

  // Final fallback: software
  const sw = new SoftwareTrustAnchor();
  await sw.initialize();
  return sw;
}

function createAnchorByType(type: string): TrustAnchor | null {
  switch (type) {
    case "software":
      return new SoftwareTrustAnchor();
    case "tpm":
      return new TPMTrustAnchor();
    case "sgx":
      return new SGXTrustAnchor();
    case "firecracker":
      return new FirecrackerTrustAnchor();
    default:
      return null;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────

function createPublicKeyFromHex(hex: string): KeyObject {
  const der = Buffer.from(hex, "hex");
  return require("crypto").createPublicKey({
    key: der,
    format: "der",
    type: "spki",
  });
}

/** Error thrown by stub trust anchors that require hardware not present. */
export class NotImplementedError extends Error {
  constructor(anchorType: string, requirement: string) {
    super(`${anchorType} trust anchor is not implemented. Requires: ${requirement}`);
    this.name = "NotImplementedError";
  }
}
