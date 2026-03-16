// ─── Human Override Module ──────────────────────────────────────────
import crypto from "node:crypto";
import type { HumanOverride } from "../types.js";

/** Ed25519 SPKI DER prefix (12 bytes). */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Ed25519 PKCS8 DER prefix (16 bytes). */
const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

/**
 * Manages cryptographically signed human overrides of automated decisions.
 */
export class HumanOverrideManager {
  private overrides: HumanOverride[] = [];

  /**
   * Record a new human override after verifying its Ed25519 signature.
   *
   * @throws Error if the signature is invalid.
   */
  async recordOverride(
    input: Omit<HumanOverride, "override_id">,
  ): Promise<HumanOverride> {
    // Build a temporary full object with a placeholder ID for signature verification
    const tempOverride: HumanOverride = { ...input, override_id: "" };

    if (!this.verifySignature(tempOverride)) {
      throw new Error("Invalid override signature");
    }

    const override: HumanOverride = {
      ...input,
      override_id: crypto.randomUUID(),
    };

    this.overrides.push(override);
    return override;
  }

  /**
   * Verify the Ed25519 signature on a human override.
   *
   * The payload that was signed is the canonical JSON produced by
   * `generateSignablePayload`. The public key and signature are hex-encoded.
   */
  verifySignature(override: HumanOverride): boolean {
    try {
      const payload = HumanOverrideManager.generateSignablePayload(override);
      const publicKeyRaw = Buffer.from(override.public_key, "hex");
      const derBytes = Buffer.concat([ED25519_SPKI_PREFIX, publicKeyRaw]);
      const keyObject = crypto.createPublicKey({
        key: derBytes,
        format: "der",
        type: "spki",
      });
      const signature = Buffer.from(override.signature, "hex");
      return crypto.verify(null, Buffer.from(payload), keyObject, signature);
    } catch {
      return false;
    }
  }

  /**
   * Return all overrides for a specific decision.
   */
  getOverridesForDecision(decisionId: string): HumanOverride[] {
    return this.overrides.filter((o) => o.decision_id === decisionId);
  }

  /**
   * Return an immutable view of all recorded overrides.
   */
  getAllOverrides(): ReadonlyArray<HumanOverride> {
    return this.overrides;
  }

  /**
   * Generate a canonical JSON string with sorted keys for signing.
   * Only includes the fields relevant to the override payload (not override_id).
   */
  static generateSignablePayload(params: {
    decision_id: string;
    action: string;
    reason: string;
    overrider_id: string;
    timestamp: string;
  }): string {
    const obj: Record<string, string> = {
      action: params.action,
      decision_id: params.decision_id,
      overrider_id: params.overrider_id,
      reason: params.reason,
      timestamp: params.timestamp,
    };
    // Keys are already in alphabetical order; JSON.stringify with sorted keys
    const sortedKeys = Object.keys(obj).sort();
    const sorted: Record<string, string> = {};
    for (const key of sortedKeys) {
      sorted[key] = obj[key];
    }
    return JSON.stringify(sorted);
  }
}

/**
 * Generate an Ed25519 key pair.
 *
 * @returns Hex-encoded raw 32-byte public and private keys.
 */
export function generateEd25519KeyPair(): {
  publicKey: string;
  privateKey: string;
} {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");

  const publicDer = publicKey.export({ type: "spki", format: "der" });
  const rawPublic = publicDer.subarray(publicDer.length - 32);

  const privateDer = privateKey.export({ type: "pkcs8", format: "der" });
  const rawPrivate = privateDer.subarray(privateDer.length - 32);

  return {
    publicKey: rawPublic.toString("hex"),
    privateKey: rawPrivate.toString("hex"),
  };
}

/**
 * Sign an override payload with a hex-encoded Ed25519 private key.
 *
 * @param payload       - The canonical JSON string to sign.
 * @param privateKeyHex - Hex-encoded raw 32-byte Ed25519 private key.
 * @returns Hex-encoded signature.
 */
export function signOverridePayload(
  payload: string,
  privateKeyHex: string,
): string {
  const privateKeyRaw = Buffer.from(privateKeyHex, "hex");
  const derBytes = Buffer.concat([ED25519_PKCS8_PREFIX, privateKeyRaw]);
  const keyObject = crypto.createPrivateKey({
    key: derBytes,
    format: "der",
    type: "pkcs8",
  });
  const signature = crypto.sign(null, Buffer.from(payload), keyObject);
  return signature.toString("hex");
}
