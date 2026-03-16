import { describe, it, expect, beforeEach } from "vitest";
import { HumanOverrideManager, generateEd25519KeyPair, signOverridePayload } from "../src/engine/human-override.js";

describe("HumanOverrideManager", () => {
  let manager: HumanOverrideManager;
  let keys: { publicKey: string; privateKey: string };

  beforeEach(() => {
    manager = new HumanOverrideManager();
    keys = generateEd25519KeyPair();
  });

  /** Helper to create a valid signed override input. */
  function makeSignedInput(
    overrides?: Partial<{
      decision_id: string;
      action: "approve" | "reject" | "escalate";
      reason: string;
      overrider_id: string;
      timestamp: string;
    }>,
  ) {
    const params = {
      decision_id: overrides?.decision_id ?? "dec-001",
      action: overrides?.action ?? ("approve" as const),
      reason: overrides?.reason ?? "Manually reviewed and approved",
      overrider_id: overrides?.overrider_id ?? "user-admin",
      timestamp: overrides?.timestamp ?? "2026-03-16T12:00:00Z",
    };
    const payload = HumanOverrideManager.generateSignablePayload(params);
    const signature = signOverridePayload(payload, keys.privateKey);
    return {
      ...params,
      signature,
      public_key: keys.publicKey,
    };
  }

  // ── Key generation ─────────────────────────────────────────────────

  it("generates a valid Ed25519 key pair with 32-byte hex keys", () => {
    expect(keys.publicKey).toHaveLength(64); // 32 bytes = 64 hex chars
    expect(keys.privateKey).toHaveLength(64);
    // Should be valid hex
    expect(/^[0-9a-f]{64}$/.test(keys.publicKey)).toBe(true);
    expect(/^[0-9a-f]{64}$/.test(keys.privateKey)).toBe(true);
  });

  // ── Sign and verify roundtrip ──────────────────────────────────────

  it("signs and verifies a payload successfully", () => {
    const payload = HumanOverrideManager.generateSignablePayload({
      decision_id: "dec-001",
      action: "approve",
      reason: "Looks good",
      overrider_id: "admin",
      timestamp: "2026-03-16T00:00:00Z",
    });
    const signature = signOverridePayload(payload, keys.privateKey);
    const override = {
      override_id: "",
      decision_id: "dec-001",
      action: "approve" as const,
      reason: "Looks good",
      overrider_id: "admin",
      timestamp: "2026-03-16T00:00:00Z",
      signature,
      public_key: keys.publicKey,
    };
    expect(manager.verifySignature(override)).toBe(true);
  });

  // ── Invalid signature rejected ─────────────────────────────────────

  it("rejects an invalid signature", () => {
    const override = {
      override_id: "",
      decision_id: "dec-001",
      action: "approve" as const,
      reason: "Looks good",
      overrider_id: "admin",
      timestamp: "2026-03-16T00:00:00Z",
      signature: "00".repeat(64), // bogus signature
      public_key: keys.publicKey,
    };
    expect(manager.verifySignature(override)).toBe(false);
  });

  // ── recordOverride with valid signature ────────────────────────────

  it("records an override with a valid signature", async () => {
    const input = makeSignedInput();
    const result = await manager.recordOverride(input);

    expect(result.override_id).toBeDefined();
    expect(result.override_id.length).toBeGreaterThan(0);
    expect(result.decision_id).toBe("dec-001");
    expect(result.action).toBe("approve");
    expect(result.reason).toBe("Manually reviewed and approved");
  });

  // ── recordOverride with invalid signature throws ───────────────────

  it("throws on recordOverride with invalid signature", async () => {
    const input = makeSignedInput();
    input.signature = "ff".repeat(64);
    await expect(manager.recordOverride(input)).rejects.toThrow("Invalid override signature");
  });

  // ── getOverridesForDecision filters correctly ──────────────────────

  it("filters overrides by decision ID", async () => {
    const input1 = makeSignedInput({ decision_id: "dec-001" });
    const input2 = makeSignedInput({ decision_id: "dec-002" });
    const input3 = makeSignedInput({ decision_id: "dec-001", action: "reject", reason: "Rejected after review" });

    await manager.recordOverride(input1);
    await manager.recordOverride(input2);
    await manager.recordOverride(input3);

    const forDec1 = manager.getOverridesForDecision("dec-001");
    expect(forDec1).toHaveLength(2);
    expect(forDec1.every((o) => o.decision_id === "dec-001")).toBe(true);

    const forDec2 = manager.getOverridesForDecision("dec-002");
    expect(forDec2).toHaveLength(1);
    expect(forDec2[0].decision_id).toBe("dec-002");

    const forDec3 = manager.getOverridesForDecision("dec-999");
    expect(forDec3).toHaveLength(0);
  });

  // ── generateSignablePayload produces consistent output ─────────────

  it("generates a canonical JSON payload with sorted keys", () => {
    const payload = HumanOverrideManager.generateSignablePayload({
      decision_id: "dec-001",
      action: "approve",
      reason: "OK",
      overrider_id: "admin",
      timestamp: "2026-01-01T00:00:00Z",
    });
    const parsed = JSON.parse(payload);
    const keys = Object.keys(parsed);
    expect(keys).toEqual(["action", "decision_id", "overrider_id", "reason", "timestamp"]);
  });

  // ── generateSignablePayload is deterministic ───────────────────────

  it("produces the same output for the same inputs (deterministic)", () => {
    const params = {
      decision_id: "dec-xyz",
      action: "escalate",
      reason: "Needs more review",
      overrider_id: "user-42",
      timestamp: "2026-06-15T08:30:00Z",
    };
    const payload1 = HumanOverrideManager.generateSignablePayload(params);
    const payload2 = HumanOverrideManager.generateSignablePayload(params);
    expect(payload1).toBe(payload2);
  });

  // ── Override gets unique ID ────────────────────────────────────────

  it("assigns a unique override_id to each recorded override", async () => {
    const input1 = makeSignedInput();
    const input2 = makeSignedInput({ reason: "Second approval" });

    const result1 = await manager.recordOverride(input1);
    const result2 = await manager.recordOverride(input2);

    expect(result1.override_id).toBeDefined();
    expect(result2.override_id).toBeDefined();
    expect(result1.override_id).not.toBe(result2.override_id);
  });

  // ── Verify signature on recorded override ──────────────────────────

  it("verifies the signature on a recorded override", async () => {
    const input = makeSignedInput();
    const recorded = await manager.recordOverride(input);
    expect(manager.verifySignature(recorded)).toBe(true);
  });

  // ── Multiple overrides for same decision ───────────────────────────

  it("supports multiple overrides for the same decision", async () => {
    const input1 = makeSignedInput({ action: "approve", reason: "First approval" });
    const input2 = makeSignedInput({ action: "reject", reason: "Changed mind" });
    const input3 = makeSignedInput({ action: "escalate", reason: "Escalating" });

    await manager.recordOverride(input1);
    await manager.recordOverride(input2);
    await manager.recordOverride(input3);

    const overrides = manager.getOverridesForDecision("dec-001");
    expect(overrides).toHaveLength(3);
    expect(overrides.map((o) => o.action)).toEqual(["approve", "reject", "escalate"]);
  });

  // ── getAllOverrides returns all recorded overrides ──────────────────

  it("returns all recorded overrides via getAllOverrides", async () => {
    expect(manager.getAllOverrides()).toHaveLength(0);

    const input1 = makeSignedInput({ decision_id: "dec-001" });
    const input2 = makeSignedInput({ decision_id: "dec-002" });

    await manager.recordOverride(input1);
    await manager.recordOverride(input2);

    const all = manager.getAllOverrides();
    expect(all).toHaveLength(2);
    expect(all[0].decision_id).toBe("dec-001");
    expect(all[1].decision_id).toBe("dec-002");
  });
});
