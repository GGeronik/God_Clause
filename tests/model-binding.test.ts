import { describe, it, expect } from "vitest";
import { ModelBindingVerifier } from "../src/engine/model-binding.js";
import type { ModelBinding } from "../src/types.js";

const bindings: ModelBinding[] = [
  {
    model_id: "gpt-4-turbo",
    provider: "openai",
    sha256: "abc123hash",
    allowed_actions: ["generate", "summarize"],
    max_tokens: 4096,
    temperature_max: 0.7,
  },
  {
    model_id: "claude-3-opus",
    provider: "anthropic",
    // no sha256 — hash verification not required
    max_tokens: 8192,
    temperature_max: 1.0,
  },
  {
    model_id: "llama-3",
    provider: "meta",
    sha256: "def456hash",
    // no allowed_actions — all actions permitted
  },
];

describe("ModelBindingVerifier", () => {
  const verifier = new ModelBindingVerifier(bindings);

  // ── verify() ────────────────────────────────────────────────────────

  it("allows a model that is in the bindings (no hash required)", () => {
    const result = verifier.verify("claude-3-opus", "anthropic");
    expect(result.allowed).toBe(true);
    expect(result.binding?.model_id).toBe("claude-3-opus");
    expect(result.reason).toBeUndefined();
  });

  it("denies a model not present in bindings", () => {
    const result = verifier.verify("unknown-model", "openai");
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("model_not_in_bindings");
    expect(result.binding).toBeUndefined();
  });

  it("allows a model when the artifact hash matches", () => {
    const result = verifier.verify("gpt-4-turbo", "openai", "abc123hash");
    expect(result.allowed).toBe(true);
    expect(result.binding?.sha256).toBe("abc123hash");
  });

  it("denies a model when the artifact hash does not match", () => {
    const result = verifier.verify("gpt-4-turbo", "openai", "wrong_hash");
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("hash_mismatch");
    expect(result.binding).toBeDefined();
  });

  it("denies when hash is required but not provided", () => {
    const result = verifier.verify("gpt-4-turbo", "openai");
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("hash_not_provided");
    expect(result.binding?.model_id).toBe("gpt-4-turbo");
  });

  // ── isActionAllowed() ───────────────────────────────────────────────

  it("allows an action that is in the allowed_actions list", () => {
    expect(verifier.isActionAllowed("gpt-4-turbo", "generate")).toBe(true);
    expect(verifier.isActionAllowed("gpt-4-turbo", "summarize")).toBe(true);
  });

  it("denies an action not in the allowed_actions list", () => {
    expect(verifier.isActionAllowed("gpt-4-turbo", "translate")).toBe(false);
  });

  it("allows any action when allowed_actions is undefined", () => {
    expect(verifier.isActionAllowed("claude-3-opus", "generate")).toBe(true);
    expect(verifier.isActionAllowed("claude-3-opus", "anything_goes")).toBe(true);
  });

  // ── getConstraints() ────────────────────────────────────────────────

  it("returns correct constraints for a known model", () => {
    const constraints = verifier.getConstraints("gpt-4-turbo");
    expect(constraints).not.toBeNull();
    expect(constraints!.max_tokens).toBe(4096);
    expect(constraints!.temperature_max).toBe(0.7);
    expect(constraints!.allowed_actions).toEqual(["generate", "summarize"]);
  });

  it("returns null for an unknown model", () => {
    expect(verifier.getConstraints("nonexistent-model")).toBeNull();
  });

  // ── getBindings() ───────────────────────────────────────────────────

  it("returns all bindings as a readonly array", () => {
    const result = verifier.getBindings();
    expect(result).toHaveLength(3);
    expect(result[0].model_id).toBe("gpt-4-turbo");
  });
});
