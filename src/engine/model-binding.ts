// ─── Model Hash Binding Module ──────────────────────────────────────
import type { ModelBinding, ModelBindingResult } from "../types.js";

/**
 * Verifies that AI models are permitted by the trust contract's model bindings
 * and optionally checks SHA-256 artifact hashes for integrity.
 */
export class ModelBindingVerifier {
  private readonly bindings: ModelBinding[];

  constructor(bindings: ModelBinding[]) {
    this.bindings = [...bindings];
  }

  /**
   * Verify whether a model is allowed under the current bindings.
   *
   * @param modelId  - Model identifier (e.g. "gpt-4-turbo")
   * @param provider - Provider name (e.g. "openai")
   * @param artifactHash - Optional SHA-256 hash of the model artifact
   */
  verify(modelId: string, provider: string, artifactHash?: string): ModelBindingResult {
    const binding = this.bindings.find(
      (b) => b.model_id === modelId && b.provider === provider,
    );

    if (!binding) {
      return { allowed: false, reason: "model_not_in_bindings" };
    }

    if (binding.sha256) {
      if (artifactHash === undefined || artifactHash === null) {
        return { allowed: false, binding, reason: "hash_not_provided" };
      }
      if (binding.sha256 !== artifactHash) {
        return { allowed: false, binding, reason: "hash_mismatch" };
      }
    }

    return { allowed: true, binding };
  }

  /**
   * Return the operational constraints for a model (any provider).
   * Returns null if the model is not found in any binding.
   */
  getConstraints(
    modelId: string,
  ): { max_tokens?: number; temperature_max?: number; allowed_actions?: string[] } | null {
    const binding = this.bindings.find((b) => b.model_id === modelId);
    if (!binding) {
      return null;
    }
    return {
      ...(binding.max_tokens !== undefined && { max_tokens: binding.max_tokens }),
      ...(binding.temperature_max !== undefined && { temperature_max: binding.temperature_max }),
      ...(binding.allowed_actions !== undefined && { allowed_actions: binding.allowed_actions }),
    };
  }

  /**
   * Check whether a specific action is allowed for a model.
   * If allowed_actions is undefined or empty, all actions are permitted.
   */
  isActionAllowed(modelId: string, action: string): boolean {
    const binding = this.bindings.find((b) => b.model_id === modelId);
    if (!binding) {
      return false;
    }
    if (!binding.allowed_actions || binding.allowed_actions.length === 0) {
      return true;
    }
    return binding.allowed_actions.includes(action);
  }

  /** Return an immutable view of the configured bindings. */
  getBindings(): ReadonlyArray<ModelBinding> {
    return this.bindings;
  }
}
