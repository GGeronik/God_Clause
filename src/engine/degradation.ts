import type { DegradationTier } from "../types";

/**
 * Manages progressive capability degradation based on system health triggers.
 *
 * When attestation failures, audit errors, or other anomalies occur, the
 * DegradationManager escalates to more restrictive tiers, blocking dangerous
 * actions while keeping safe operations available.
 */
export class DegradationManager {
  private readonly tiers: DegradationTier[];
  private currentTier: number = 0;
  private readonly onNotify?: (tier: DegradationTier) => void | Promise<void>;

  constructor(tiers: DegradationTier[], onNotify?: (tier: DegradationTier) => void | Promise<void>) {
    // Ensure tiers are sorted ascending by tier number
    this.tiers = [...tiers].sort((a, b) => a.tier - b.tier);
    this.onNotify = onNotify;
  }

  /**
   * Trigger degradation by reason string.
   *
   * Finds the first tier whose `trigger` matches the given reason.
   * If the matched tier is more restrictive (higher number) than the current
   * tier, escalates and fires the notification callback.
   *
   * @returns The activated tier definition, or null if no change occurred.
   */
  trigger(reason: string): DegradationTier | null {
    const matched = this.tiers.find((t) => t.trigger === reason);
    if (!matched) return null;

    if (matched.tier <= this.currentTier) return null;

    this.currentTier = matched.tier;
    if (this.onNotify) {
      this.onNotify(matched);
    }
    return matched;
  }

  /**
   * Recover to a lower degradation tier.
   *
   * @param toTier - Tier number to recover to (default: 0, fully operational).
   */
  recover(toTier: number = 0): void {
    this.currentTier = toTier;
  }

  /**
   * Check whether an action is allowed at the current degradation tier.
   *
   * At tier 0 (fully operational), all actions are allowed.
   * At higher tiers, actions listed in `blocked_actions` are denied.
   */
  isActionAllowed(action: string): boolean {
    if (this.currentTier === 0) return true;

    const tierDef = this.tiers.find((t) => t.tier === this.currentTier);
    if (!tierDef) return true;

    return !tierDef.blocked_actions.includes(action);
  }

  /** Returns the current tier number. */
  getCurrentTier(): number {
    return this.currentTier;
  }

  /** Returns the tier definition for the current tier, or null if at tier 0 with no tier 0 definition. */
  getCurrentTierDefinition(): DegradationTier | null {
    return this.tiers.find((t) => t.tier === this.currentTier) ?? null;
  }

  /** Returns a readonly view of all configured tiers. */
  getTiers(): ReadonlyArray<DegradationTier> {
    return this.tiers;
  }
}
