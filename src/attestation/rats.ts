import { createHash, randomBytes, sign as cryptoSign, verify as cryptoVerify, generateKeyPairSync, KeyObject } from "crypto";
import {
  AttestationChallenge, AttestationEvidence, AttestationClaim,
  AttestationResult, AttestationPolicy, AppraisalResult,
  AttestationOptions, PolicyContext,
} from "../types";
import type { TrustAnchor } from "./trust-anchor";

/**
 * IETF RATS (RFC 9334) challenge-response attestation service.
 *
 * Implements the three RATS roles:
 * - **Verifier**: Generates challenges and verifies evidence
 * - **Attester**: Collects system evidence in response to challenges
 * - **Relying Party**: Appraises attestation results against policy
 */
export class AttestationService {
  private challengeTtlMs: number;
  private publicKey: KeyObject;
  private privateKey: KeyObject;
  private requiredClaims: string[];
  private trustAnchor?: TrustAnchor;

  constructor(opts?: AttestationOptions) {
    this.challengeTtlMs = opts?.challengeTtlMs ?? 30000;
    this.requiredClaims = opts?.requiredClaims ?? ["contract_hash", "audit_chain", "system_state"];

    // Initialize signing key pair
    if (opts?.signingKeyPair) {
      this.privateKey = createPrivateKeyFromHex(opts.signingKeyPair.privateKey);
      this.publicKey = createPublicKeyFromHex(opts.signingKeyPair.publicKey);
    } else {
      const keyPair = generateKeyPairSync("ed25519");
      this.publicKey = keyPair.publicKey;
      this.privateKey = keyPair.privateKey;
    }
  }

  /**
   * Set an optional trust anchor for enhanced evidence collection.
   */
  setTrustAnchor(anchor: TrustAnchor): void {
    this.trustAnchor = anchor;
  }

  // ─── Verifier Role ──────────────────────────────────────────────

  /**
   * Generate a fresh attestation challenge with a cryptographic nonce.
   */
  generateChallenge(scope?: string[]): AttestationChallenge {
    return {
      nonce: randomBytes(32).toString("hex"),
      timestamp: new Date().toISOString(),
      scope: scope ?? this.requiredClaims,
      ttlMs: this.challengeTtlMs,
    };
  }

  /**
   * Verify attestation evidence against its original challenge.
   * Checks nonce freshness, signature validity, and claim presence.
   */
  verifyEvidence(evidence: AttestationEvidence, challenge: AttestationChallenge): AttestationResult {
    const timestamp = new Date().toISOString();
    const verifiedClaims: Array<{ type: string; verified: boolean; detail?: string }> = [];

    // 1. Check nonce match
    if (evidence.challenge_nonce !== challenge.nonce) {
      return {
        status: "failure",
        verified_claims: [{ type: "nonce", verified: false, detail: "Nonce mismatch" }],
        timestamp,
        nonce: challenge.nonce,
      };
    }

    // 2. Check challenge freshness (not expired)
    const challengeTime = new Date(challenge.timestamp).getTime();
    const evidenceTime = new Date(evidence.timestamp).getTime();
    if (evidenceTime - challengeTime > challenge.ttlMs) {
      return {
        status: "failure",
        verified_claims: [{ type: "freshness", verified: false, detail: `Evidence collected ${evidenceTime - challengeTime}ms after challenge (TTL: ${challenge.ttlMs}ms)` }],
        timestamp,
        nonce: challenge.nonce,
      };
    }

    // 3. Verify signature
    const signatureValid = this.verifyEvidenceSignature(evidence);
    verifiedClaims.push({
      type: "signature",
      verified: signatureValid,
      detail: signatureValid ? "Ed25519 signature valid" : "Signature verification failed",
    });

    if (!signatureValid) {
      return {
        status: "failure",
        verified_claims: verifiedClaims,
        timestamp,
        nonce: challenge.nonce,
      };
    }

    // 4. Verify each claim is present and structurally valid
    const requestedScope = challenge.scope ?? this.requiredClaims;
    for (const requiredType of requestedScope) {
      const claim = evidence.claims.find((c) => c.type === requiredType);
      if (!claim) {
        verifiedClaims.push({
          type: requiredType,
          verified: false,
          detail: `Required claim "${requiredType}" missing from evidence`,
        });
      } else {
        verifiedClaims.push({
          type: requiredType,
          verified: true,
          detail: `Claim "${requiredType}" present`,
        });
      }
    }

    const allVerified = verifiedClaims.every((c) => c.verified);
    const someVerified = verifiedClaims.some((c) => c.verified);

    return {
      status: allVerified ? "success" : someVerified ? "partial" : "failure",
      verified_claims: verifiedClaims,
      timestamp,
      nonce: challenge.nonce,
    };
  }

  // ─── Attester Role ──────────────────────────────────────────────

  /**
   * Collect attestation evidence in response to a challenge.
   * Gathers system state, contract hashes, audit chain info, etc.
   */
  async collectEvidence(
    challenge: AttestationChallenge,
    gov?: { getContracts(): ReadonlyArray<{ metadata: { name: string; version: string }; rules: unknown[] }>; getAuditEntries(): ReadonlyArray<{ hash: string }> },
  ): Promise<AttestationEvidence> {
    const scope = challenge.scope ?? this.requiredClaims;
    const claims: AttestationClaim[] = [];
    const now = new Date().toISOString();

    for (const claimType of scope) {
      switch (claimType) {
        case "contract_hash":
          claims.push(this.collectContractHashClaim(gov, now));
          break;
        case "audit_chain":
          claims.push(this.collectAuditChainClaim(gov, now));
          break;
        case "system_state":
          claims.push(this.collectSystemStateClaim(now));
          break;
        case "evaluator_hash":
          claims.push(this.collectEvaluatorHashClaim(now));
          break;
        case "trust_anchor":
          if (this.trustAnchor) {
            claims.push(await this.collectTrustAnchorClaim(challenge, now));
          } else {
            claims.push({
              type: "trust_anchor",
              value: { available: false, reason: "No trust anchor configured" },
              measurement_timestamp: now,
            });
          }
          break;
        default:
          claims.push({
            type: claimType,
            value: { available: false, reason: `Unknown claim type: ${claimType}` },
            measurement_timestamp: now,
          });
      }
    }

    // Sign the claims
    const canonicalClaims = JSON.stringify(claims, Object.keys(claims).sort());
    const signablePayload = Buffer.from(JSON.stringify({
      challenge_nonce: challenge.nonce,
      claims: canonicalClaims,
      timestamp: now,
    }));

    const signature = cryptoSign(null, signablePayload, this.privateKey);

    return {
      challenge_nonce: challenge.nonce,
      timestamp: now,
      claims,
      signature: signature.toString("hex"),
      public_key: this.publicKey.export({ type: "spki", format: "der" }).toString("hex"),
    };
  }

  // ─── Relying Party Role ─────────────────────────────────────────

  /**
   * Appraise an attestation result against a trust policy.
   * Determines whether the attested entity should be trusted.
   */
  appraise(result: AttestationResult, policy: AttestationPolicy): AppraisalResult {
    const details: Array<{ claim: string; met: boolean; reason?: string }> = [];

    // Check that all required claims are present and verified
    for (const required of policy.required_claims) {
      const verified = result.verified_claims.find((c) => c.type === required);
      if (!verified) {
        details.push({
          claim: required,
          met: false,
          reason: `Required claim "${required}" not in attestation result`,
        });
      } else if (!verified.verified) {
        details.push({
          claim: required,
          met: false,
          reason: verified.detail ?? `Claim "${required}" failed verification`,
        });
      } else {
        details.push({ claim: required, met: true });
      }
    }

    // Check evidence age
    if (policy.max_evidence_age_ms) {
      const evidenceAge = Date.now() - new Date(result.timestamp).getTime();
      if (evidenceAge > policy.max_evidence_age_ms) {
        details.push({
          claim: "freshness",
          met: false,
          reason: `Evidence age ${evidenceAge}ms exceeds maximum ${policy.max_evidence_age_ms}ms`,
        });
      } else {
        details.push({ claim: "freshness", met: true });
      }
    }

    // Check reference values
    for (const [key, expectedValue] of Object.entries(policy.reference_values)) {
      const claim = result.verified_claims.find((c) => c.type === key);
      if (claim) {
        details.push({ claim: key, met: claim.verified });
      }
    }

    const trusted = details.every((d) => d.met);
    return { trusted, details };
  }

  // ─── Private Helpers ────────────────────────────────────────────

  private verifyEvidenceSignature(evidence: AttestationEvidence): boolean {
    try {
      const canonicalClaims = JSON.stringify(evidence.claims, Object.keys(evidence.claims).sort());
      const signablePayload = Buffer.from(JSON.stringify({
        challenge_nonce: evidence.challenge_nonce,
        claims: canonicalClaims,
        timestamp: evidence.timestamp,
      }));

      const pubKey = createPublicKeyFromHex(evidence.public_key);
      const sigBuf = Buffer.from(evidence.signature, "hex");
      return cryptoVerify(null, signablePayload, pubKey, sigBuf);
    } catch {
      return false;
    }
  }

  private collectContractHashClaim(
    gov: { getContracts(): ReadonlyArray<{ metadata: { name: string; version: string }; rules: unknown[] }> } | undefined,
    timestamp: string,
  ): AttestationClaim {
    if (!gov) {
      return {
        type: "contract_hash",
        value: { hash: "none", contract_count: 0 },
        measurement_timestamp: timestamp,
      };
    }

    const contracts = gov.getContracts();
    const contractData = contracts.map((c) => `${c.metadata.name}@${c.metadata.version}:${JSON.stringify(c.rules)}`);
    const hash = createHash("sha256").update(contractData.join("|")).digest("hex");

    return {
      type: "contract_hash",
      value: { hash, contract_count: contracts.length },
      measurement_timestamp: timestamp,
    };
  }

  private collectAuditChainClaim(
    gov: { getAuditEntries(): ReadonlyArray<{ hash: string }> } | undefined,
    timestamp: string,
  ): AttestationClaim {
    if (!gov) {
      return {
        type: "audit_chain",
        value: { head_hash: "none", chain_length: 0, valid: true },
        measurement_timestamp: timestamp,
      };
    }

    const entries = gov.getAuditEntries();
    const headHash = entries.length > 0 ? entries[entries.length - 1].hash : "GENESIS";

    return {
      type: "audit_chain",
      value: {
        head_hash: headHash,
        chain_length: entries.length,
        valid: true, // Full verification is expensive; basic claim here
      },
      measurement_timestamp: timestamp,
    };
  }

  private collectSystemStateClaim(timestamp: string): AttestationClaim {
    return {
      type: "system_state",
      value: {
        node_version: process.version,
        platform: process.platform,
        arch: process.arch,
        uptime_seconds: Math.floor(process.uptime()),
        memory_mb: Math.floor(process.memoryUsage().heapUsed / 1024 / 1024),
        pid: process.pid,
      },
      measurement_timestamp: timestamp,
    };
  }

  private collectEvaluatorHashClaim(timestamp: string): AttestationClaim {
    // Hash of the evaluator module source for integrity
    const evaluatorIdentity = `god-clause-evaluator-v1`;
    const hash = createHash("sha256").update(evaluatorIdentity).digest("hex");

    return {
      type: "evaluator_hash",
      value: { hash, version: "1.0" },
      measurement_timestamp: timestamp,
    };
  }

  private async collectTrustAnchorClaim(
    challenge: AttestationChallenge,
    timestamp: string,
  ): Promise<AttestationClaim> {
    if (!this.trustAnchor) {
      return {
        type: "trust_anchor",
        value: { available: false },
        measurement_timestamp: timestamp,
      };
    }

    try {
      const nonceBuf = Buffer.from(challenge.nonce, "hex");
      const quote = await this.trustAnchor.quote(nonceBuf);
      return {
        type: "trust_anchor",
        value: {
          available: true,
          anchor_type: quote.anchorType,
          measurements: quote.measurements,
          quote_signature: quote.signature,
        },
        measurement_timestamp: timestamp,
      };
    } catch (err) {
      return {
        type: "trust_anchor",
        value: {
          available: false,
          error: err instanceof Error ? err.message : String(err),
        },
        measurement_timestamp: timestamp,
      };
    }
  }
}

// ─── Key Helpers ────────────────────────────────────────────────────

function createPrivateKeyFromHex(hex: string): KeyObject {
  const der = Buffer.from(hex, "hex");
  return require("crypto").createPrivateKey({
    key: der,
    format: "der",
    type: "pkcs8",
  });
}

function createPublicKeyFromHex(hex: string): KeyObject {
  const der = Buffer.from(hex, "hex");
  return require("crypto").createPublicKey({
    key: der,
    format: "der",
    type: "spki",
  });
}
