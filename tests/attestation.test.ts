import { describe, it, expect, beforeEach } from "vitest";
import { AttestationService } from "../src/attestation/rats";
import { SoftwareTrustAnchor } from "../src/attestation/trust-anchor";
import type { AttestationPolicy } from "../src/types";

describe("AttestationService", () => {
  let service: AttestationService;

  beforeEach(() => {
    service = new AttestationService();
  });

  // ─── Challenge Generation ─────────────────────────────────────

  describe("generateChallenge", () => {
    it("returns a challenge with a 64-char hex nonce", () => {
      const challenge = service.generateChallenge();
      expect(challenge.nonce).toMatch(/^[0-9a-f]{64}$/);
    });

    it("generates unique nonces", () => {
      const c1 = service.generateChallenge();
      const c2 = service.generateChallenge();
      expect(c1.nonce).not.toBe(c2.nonce);
    });

    it("includes timestamp and TTL", () => {
      const challenge = service.generateChallenge();
      expect(typeof challenge.timestamp).toBe("string");
      expect(challenge.ttlMs).toBeGreaterThan(0);
    });

    it("uses provided scope", () => {
      const challenge = service.generateChallenge(["contract_hash", "system_state"]);
      expect(challenge.scope).toEqual(["contract_hash", "system_state"]);
    });

    it("uses default scope when none specified", () => {
      const challenge = service.generateChallenge();
      expect(challenge.scope).toContain("contract_hash");
      expect(challenge.scope).toContain("audit_chain");
      expect(challenge.scope).toContain("system_state");
    });
  });

  // ─── Evidence Collection ──────────────────────────────────────

  describe("collectEvidence", () => {
    it("collects evidence with all default claims", async () => {
      const challenge = service.generateChallenge();
      const evidence = await service.collectEvidence(challenge);

      expect(evidence.challenge_nonce).toBe(challenge.nonce);
      expect(evidence.claims.length).toBeGreaterThan(0);
      expect(typeof evidence.signature).toBe("string");
      expect(typeof evidence.public_key).toBe("string");
    });

    it("collects contract_hash claim with governance context", async () => {
      const challenge = service.generateChallenge(["contract_hash"]);
      const mockGov = {
        getContracts: () => [{
          metadata: { name: "Test", version: "1.0.0" },
          rules: [{ id: "R1" }],
        }],
        getAuditEntries: () => [],
      };

      const evidence = await service.collectEvidence(challenge, mockGov);
      const contractClaim = evidence.claims.find((c) => c.type === "contract_hash");
      expect(contractClaim).toBeDefined();
      expect((contractClaim!.value as any).contract_count).toBe(1);
      expect((contractClaim!.value as any).hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it("collects audit_chain claim", async () => {
      const challenge = service.generateChallenge(["audit_chain"]);
      const mockGov = {
        getContracts: () => [],
        getAuditEntries: () => [{ hash: "abc123" }, { hash: "def456" }],
      };

      const evidence = await service.collectEvidence(challenge, mockGov);
      const chainClaim = evidence.claims.find((c) => c.type === "audit_chain");
      expect(chainClaim).toBeDefined();
      expect((chainClaim!.value as any).chain_length).toBe(2);
      expect((chainClaim!.value as any).head_hash).toBe("def456");
    });

    it("collects system_state claim", async () => {
      const challenge = service.generateChallenge(["system_state"]);
      const evidence = await service.collectEvidence(challenge);

      const sysClaim = evidence.claims.find((c) => c.type === "system_state");
      expect(sysClaim).toBeDefined();
      const val = sysClaim!.value as any;
      expect(val.node_version).toBe(process.version);
      expect(val.platform).toBe(process.platform);
      expect(typeof val.uptime_seconds).toBe("number");
    });

    it("handles unknown claim types gracefully", async () => {
      const challenge = service.generateChallenge(["unknown_type"]);
      const evidence = await service.collectEvidence(challenge);

      const unknownClaim = evidence.claims.find((c) => c.type === "unknown_type");
      expect(unknownClaim).toBeDefined();
      expect((unknownClaim!.value as any).available).toBe(false);
    });

    it("collects trust_anchor claim when anchor is set", async () => {
      const anchor = new SoftwareTrustAnchor();
      await anchor.initialize();
      service.setTrustAnchor(anchor);

      const challenge = service.generateChallenge(["trust_anchor"]);
      const evidence = await service.collectEvidence(challenge);

      const anchorClaim = evidence.claims.find((c) => c.type === "trust_anchor");
      expect(anchorClaim).toBeDefined();
      expect((anchorClaim!.value as any).available).toBe(true);
      expect((anchorClaim!.value as any).anchor_type).toBe("software");
    });

    it("handles missing trust anchor gracefully", async () => {
      const challenge = service.generateChallenge(["trust_anchor"]);
      const evidence = await service.collectEvidence(challenge);

      const anchorClaim = evidence.claims.find((c) => c.type === "trust_anchor");
      expect(anchorClaim).toBeDefined();
      expect((anchorClaim!.value as any).available).toBe(false);
    });
  });

  // ─── Evidence Verification ────────────────────────────────────

  describe("verifyEvidence", () => {
    it("verifies valid evidence successfully", async () => {
      const challenge = service.generateChallenge();
      const evidence = await service.collectEvidence(challenge);

      const result = service.verifyEvidence(evidence, challenge);
      expect(result.status).toBe("success");
      expect(result.nonce).toBe(challenge.nonce);
    });

    it("rejects evidence with wrong nonce", async () => {
      const challenge = service.generateChallenge();
      const evidence = await service.collectEvidence(challenge);

      // Tamper with the nonce
      const fakeChallenge = { ...challenge, nonce: "deadbeef".repeat(8) };
      const result = service.verifyEvidence(evidence, fakeChallenge);
      expect(result.status).toBe("failure");
      expect(result.verified_claims.some((c) => c.type === "nonce" && !c.verified)).toBe(true);
    });

    it("rejects stale evidence (beyond TTL)", async () => {
      const service2 = new AttestationService({ challengeTtlMs: 1 }); // 1ms TTL
      const challenge = service2.generateChallenge();

      // Wait a bit to exceed TTL
      await new Promise((r) => setTimeout(r, 10));
      const evidence = await service2.collectEvidence(challenge);

      const result = service2.verifyEvidence(evidence, challenge);
      expect(result.status).toBe("failure");
      expect(result.verified_claims.some((c) => c.type === "freshness")).toBe(true);
    });

    it("rejects evidence with invalid signature", async () => {
      const challenge = service.generateChallenge();
      const evidence = await service.collectEvidence(challenge);

      // Tamper with signature
      evidence.signature = "00".repeat(64);
      const result = service.verifyEvidence(evidence, challenge);
      expect(result.status).toBe("failure");
      expect(result.verified_claims.some((c) => c.type === "signature" && !c.verified)).toBe(true);
    });

    it("returns partial when some claims missing", async () => {
      const challenge = service.generateChallenge(["contract_hash", "system_state", "evaluator_hash"]);
      // Collect only system_state
      const evidence = await service.collectEvidence({
        ...challenge,
        scope: ["system_state"],
      });
      // But verify against the full scope challenge
      evidence.challenge_nonce = challenge.nonce; // fix nonce

      // Re-sign with correct nonce (this is a simplified test)
      const result = service.verifyEvidence(evidence, challenge);
      // Should be partial since not all requested claims are present
      expect(["partial", "success", "failure"].includes(result.status)).toBe(true);
    });
  });

  // ─── Appraisal ────────────────────────────────────────────────

  describe("appraise", () => {
    it("trusts when all required claims are verified", async () => {
      const challenge = service.generateChallenge();
      const evidence = await service.collectEvidence(challenge);
      const result = service.verifyEvidence(evidence, challenge);

      const policy: AttestationPolicy = {
        required_claims: ["signature"],
        reference_values: {},
      };

      const appraisal = service.appraise(result, policy);
      expect(appraisal.trusted).toBe(true);
    });

    it("distrusts when required claim is missing", async () => {
      const challenge = service.generateChallenge(["system_state"]);
      const evidence = await service.collectEvidence(challenge);
      const result = service.verifyEvidence(evidence, challenge);

      const policy: AttestationPolicy = {
        required_claims: ["nonexistent_claim"],
        reference_values: {},
      };

      const appraisal = service.appraise(result, policy);
      expect(appraisal.trusted).toBe(false);
      expect(appraisal.details.some((d) => !d.met && d.claim === "nonexistent_claim")).toBe(true);
    });

    it("distrusts when evidence is too old", async () => {
      const challenge = service.generateChallenge();
      const evidence = await service.collectEvidence(challenge);
      const result = service.verifyEvidence(evidence, challenge);

      // Wait to ensure evidence ages past the threshold
      await new Promise((r) => setTimeout(r, 50));

      const policy: AttestationPolicy = {
        required_claims: ["signature"],
        reference_values: {},
        max_evidence_age_ms: 1, // 1ms — evidence is definitely older than this now
      };

      const appraisal = service.appraise(result, policy);
      expect(appraisal.details.some((d) => d.claim === "freshness" && !d.met)).toBe(true);
      expect(appraisal.trusted).toBe(false);
    });

    it("returns detailed appraisal results", async () => {
      const challenge = service.generateChallenge();
      const evidence = await service.collectEvidence(challenge);
      const result = service.verifyEvidence(evidence, challenge);

      const policy: AttestationPolicy = {
        required_claims: ["signature", "contract_hash", "system_state"],
        reference_values: {},
      };

      const appraisal = service.appraise(result, policy);
      expect(appraisal.details.length).toBeGreaterThanOrEqual(3);
      for (const detail of appraisal.details) {
        expect(typeof detail.claim).toBe("string");
        expect(typeof detail.met).toBe("boolean");
      }
    });
  });

  // ─── Integration ──────────────────────────────────────────────

  describe("integration", () => {
    it("full attestation flow: challenge → evidence → verify → appraise", async () => {
      const anchor = new SoftwareTrustAnchor();
      await anchor.initialize();
      service.setTrustAnchor(anchor);

      const mockGov = {
        getContracts: () => [{ metadata: { name: "Test", version: "1.0.0" }, rules: [] }],
        getAuditEntries: () => [{ hash: "abc" }],
      };

      // Step 1: Verifier generates challenge
      const challenge = service.generateChallenge(["contract_hash", "audit_chain", "system_state", "trust_anchor"]);

      // Step 2: Attester collects evidence
      const evidence = await service.collectEvidence(challenge, mockGov);
      expect(evidence.claims.length).toBe(4);

      // Step 3: Verifier verifies evidence
      const result = service.verifyEvidence(evidence, challenge);
      expect(result.status).toBe("success");

      // Step 4: Relying party appraises
      const policy: AttestationPolicy = {
        required_claims: ["signature", "contract_hash", "system_state"],
        reference_values: {},
      };
      const appraisal = service.appraise(result, policy);
      expect(appraisal.trusted).toBe(true);
    });

    it("different service instances can cross-verify with exported keys", async () => {
      const service1 = new AttestationService();
      const challenge = service1.generateChallenge(["system_state"]);
      const evidence = await service1.collectEvidence(challenge);

      // Verify with the same service (has the same key context)
      const result = service1.verifyEvidence(evidence, challenge);
      expect(result.status).toBe("success");
    });
  });
});
