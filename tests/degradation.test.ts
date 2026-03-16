import { describe, it, expect, vi } from "vitest";
import { DegradationManager } from "../src/engine/degradation";
import type { DegradationTier } from "../src/types";

const makeTiers = (): DegradationTier[] => [
  {
    tier: 1,
    name: "reduced",
    trigger: "signature_invalid",
    capabilities: ["read", "classify"],
    blocked_actions: ["generate", "decide"],
    notify: ["ops@example.com"],
  },
  {
    tier: 2,
    name: "read-only",
    trigger: "audit_write_failed",
    capabilities: ["read"],
    blocked_actions: ["generate", "decide", "classify", "transform"],
  },
  {
    tier: 3,
    name: "locked",
    trigger: "contract_missing",
    capabilities: [],
    blocked_actions: ["*"],
  },
];

describe("DegradationManager", () => {
  it("starts at tier 0 (fully operational)", () => {
    const mgr = new DegradationManager(makeTiers());
    expect(mgr.getCurrentTier()).toBe(0);
  });

  it("trigger moves to the correct tier", () => {
    const mgr = new DegradationManager(makeTiers());
    const result = mgr.trigger("signature_invalid");
    expect(result).not.toBeNull();
    expect(result!.tier).toBe(1);
    expect(result!.name).toBe("reduced");
    expect(mgr.getCurrentTier()).toBe(1);
  });

  it("higher tier trigger overrides lower tier", () => {
    const mgr = new DegradationManager(makeTiers());
    mgr.trigger("signature_invalid"); // tier 1
    const result = mgr.trigger("audit_write_failed"); // tier 2
    expect(result).not.toBeNull();
    expect(result!.tier).toBe(2);
    expect(mgr.getCurrentTier()).toBe(2);
  });

  it("lower tier trigger is ignored when already at higher tier", () => {
    const mgr = new DegradationManager(makeTiers());
    mgr.trigger("audit_write_failed"); // tier 2
    const result = mgr.trigger("signature_invalid"); // tier 1 — should be ignored
    expect(result).toBeNull();
    expect(mgr.getCurrentTier()).toBe(2);
  });

  it("recover() resets to tier 0", () => {
    const mgr = new DegradationManager(makeTiers());
    mgr.trigger("audit_write_failed");
    expect(mgr.getCurrentTier()).toBe(2);
    mgr.recover();
    expect(mgr.getCurrentTier()).toBe(0);
  });

  it("recover(1) resets to specific tier", () => {
    const mgr = new DegradationManager(makeTiers());
    mgr.trigger("contract_missing"); // tier 3
    expect(mgr.getCurrentTier()).toBe(3);
    mgr.recover(1);
    expect(mgr.getCurrentTier()).toBe(1);
  });

  it("isActionAllowed blocks actions at degraded tier", () => {
    const mgr = new DegradationManager(makeTiers());
    mgr.trigger("signature_invalid"); // tier 1 blocks generate, decide
    expect(mgr.isActionAllowed("generate")).toBe(false);
    expect(mgr.isActionAllowed("decide")).toBe(false);
  });

  it("isActionAllowed allows non-blocked actions", () => {
    const mgr = new DegradationManager(makeTiers());
    mgr.trigger("signature_invalid"); // tier 1 blocks generate, decide
    expect(mgr.isActionAllowed("read")).toBe(true);
    expect(mgr.isActionAllowed("classify")).toBe(true);
  });

  it("isActionAllowed allows everything at tier 0", () => {
    const mgr = new DegradationManager(makeTiers());
    expect(mgr.isActionAllowed("generate")).toBe(true);
    expect(mgr.isActionAllowed("anything")).toBe(true);
  });

  it("unknown trigger returns null", () => {
    const mgr = new DegradationManager(makeTiers());
    const result = mgr.trigger("nonexistent_trigger");
    expect(result).toBeNull();
    expect(mgr.getCurrentTier()).toBe(0);
  });

  it("notification callback fires on tier change", () => {
    const callback = vi.fn();
    const mgr = new DegradationManager(makeTiers(), callback);
    mgr.trigger("signature_invalid");
    expect(callback).toHaveBeenCalledTimes(1);
    expect(callback).toHaveBeenCalledWith(
      expect.objectContaining({ tier: 1, name: "reduced" }),
    );
  });

  it("notification callback does not fire when trigger is ignored", () => {
    const callback = vi.fn();
    const mgr = new DegradationManager(makeTiers(), callback);
    mgr.trigger("audit_write_failed"); // tier 2
    callback.mockClear();
    mgr.trigger("signature_invalid"); // tier 1 — ignored
    expect(callback).not.toHaveBeenCalled();
  });

  it("getCurrentTierDefinition returns null at tier 0 with no tier 0 def", () => {
    const mgr = new DegradationManager(makeTiers());
    expect(mgr.getCurrentTierDefinition()).toBeNull();
  });

  it("getCurrentTierDefinition returns the tier definition when degraded", () => {
    const mgr = new DegradationManager(makeTiers());
    mgr.trigger("audit_write_failed");
    const def = mgr.getCurrentTierDefinition();
    expect(def).not.toBeNull();
    expect(def!.tier).toBe(2);
    expect(def!.name).toBe("read-only");
  });

  it("getTiers returns all configured tiers sorted ascending", () => {
    // Pass tiers in reverse order to verify sorting
    const reversed = makeTiers().reverse();
    const mgr = new DegradationManager(reversed);
    const tiers = mgr.getTiers();
    expect(tiers).toHaveLength(3);
    expect(tiers[0].tier).toBe(1);
    expect(tiers[1].tier).toBe(2);
    expect(tiers[2].tier).toBe(3);
  });
});
