import { createSign, createVerify, createHash } from "crypto";
import { serializeContract, parseContract } from "../contracts/parser";
import type { TrustContract } from "../types";

/**
 * Dead Simple Signing Envelope (DSSE) for trust contracts.
 *
 * DSSE provides a standard format for signing arbitrary payloads,
 * widely used in supply-chain security (Sigstore, in-toto, SLSA).
 *
 * God Clause uses DSSE to sign trust contracts, proving that a specific
 * policy was authored and approved by a known key holder.
 */
export interface DSSEEnvelope {
  payloadType: string;
  payload: string;  // base64-encoded canonical contract
  signatures: Array<{
    keyid: string;
    sig: string;    // base64-encoded signature
  }>;
}

export interface SigningOptions {
  /** PEM-encoded private key (Ed25519 or ECDSA-P256) */
  privateKey: string;
  /** Key identifier for tracking which key signed */
  keyId: string;
  /** Algorithm to use. Default: "sha256" */
  algorithm?: string;
}

export interface VerifyOptions {
  /** PEM-encoded public key */
  publicKey: string;
  /** Algorithm to use. Default: "sha256" */
  algorithm?: string;
}

const PAYLOAD_TYPE = "application/vnd.godclause.contract+yaml";

/**
 * Compute the PAE (Pre-Authentication Encoding) for DSSE.
 * PAE(payloadType, payload) = "DSSEv1" || len(payloadType) || payloadType || len(payload) || payload
 */
export function paeEncode(payloadType: string, payload: string): Buffer {
  const typeBytes = Buffer.from(payloadType, "utf-8");
  const payloadBytes = Buffer.from(payload, "utf-8");

  const prefix = Buffer.from(`DSSEv1 ${typeBytes.length} `, "utf-8");
  const middle = Buffer.from(` ${payloadBytes.length} `, "utf-8");

  return Buffer.concat([prefix, typeBytes, middle, payloadBytes]);
}

/**
 * Sign a trust contract using DSSE envelope format.
 *
 * ```ts
 * const envelope = signContract(contract, {
 *   privateKey: fs.readFileSync("key.pem", "utf-8"),
 *   keyId: "signing-key-2026",
 * });
 * ```
 */
export function signContract(contract: TrustContract, opts: SigningOptions): DSSEEnvelope {
  const canonical = serializeContract(contract);
  const payloadB64 = Buffer.from(canonical).toString("base64");

  const pae = paeEncode(PAYLOAD_TYPE, payloadB64);
  const signer = createSign(opts.algorithm ?? "sha256");
  signer.update(pae);
  const signature = signer.sign(opts.privateKey, "base64");

  return {
    payloadType: PAYLOAD_TYPE,
    payload: payloadB64,
    signatures: [
      {
        keyid: opts.keyId,
        sig: signature,
      },
    ],
  };
}

/**
 * Verify a DSSE-signed contract envelope.
 *
 * Returns the verified contract if signature is valid, or throws on failure.
 *
 * ```ts
 * const { valid, contract } = verifyContractSignature(envelope, {
 *   publicKey: fs.readFileSync("key.pub", "utf-8"),
 * });
 * ```
 */
export function verifyContractSignature(
  envelope: DSSEEnvelope,
  opts: VerifyOptions,
): { valid: boolean; contract: TrustContract; keyId?: string } {
  for (const sig of envelope.signatures) {
    const pae = paeEncode(envelope.payloadType, envelope.payload);
    const verifier = createVerify(opts.algorithm ?? "sha256");
    verifier.update(pae);

    const valid = verifier.verify(opts.publicKey, sig.sig, "base64");
    if (valid) {
      const yamlStr = Buffer.from(envelope.payload, "base64").toString("utf-8");
      const contract = parseContract(yamlStr);
      return { valid: true, contract, keyId: sig.keyid };
    }
  }

  return { valid: false, contract: {} as TrustContract };
}

/**
 * Compute a SHA-256 fingerprint of a trust contract's rules.
 * Useful for verifying that a contract hasn't been modified.
 */
export function contractFingerprint(contract: TrustContract): string {
  const sortKeys = (_key: string, value: unknown): unknown => {
    if (value && typeof value === "object" && !Array.isArray(value)) {
      const sorted: Record<string, unknown> = {};
      for (const k of Object.keys(value as Record<string, unknown>).sort()) {
        sorted[k] = (value as Record<string, unknown>)[k];
      }
      return sorted;
    }
    return value;
  };
  const canonical = JSON.stringify(contract, sortKeys);
  return createHash("sha256").update(canonical).digest("hex");
}
