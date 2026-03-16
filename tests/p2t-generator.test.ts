import { describe, it, expect } from "vitest";
import { P2TGenerator } from "../src/contracts/p2t-generator";
import { parseContract } from "../src/contracts/parser";

describe("P2T Generator", () => {
  const gen = new P2TGenerator();

  it("lists all built-in templates", () => {
    const templates = gen.listTemplates();
    expect(templates.length).toBeGreaterThanOrEqual(6);

    const ids = templates.map((t) => t.id);
    expect(ids).toContain("pii-protection");
    expect(ids).toContain("rate-limiting");
    expect(ids).toContain("content-safety");
    expect(ids).toContain("access-control");
    expect(ids).toContain("model-governance");
    expect(ids).toContain("compliance-baseline");
  });

  it("generates a valid PII protection contract", () => {
    const yaml = gen.generate({
      template: "pii-protection",
      params: { severity: "modify", replacement_text: "[HIDDEN]" },
      metadata: { name: "PII Test", author: "Test" },
    });

    expect(yaml).toContain("PII Test");
    expect(yaml).toContain("PII-001");
    expect(yaml).toContain("redact_pii");
    expect(yaml).toContain("[HIDDEN]");

    // Should be valid YAML that parses
    const contract = parseContract(yaml);
    expect(contract.metadata.name).toBe("PII Test");
    expect(contract.rules.length).toBeGreaterThanOrEqual(1);
  });

  it("generates a block-severity PII contract", () => {
    const yaml = gen.generate({
      template: "pii-protection",
      params: { severity: "block" },
    });

    expect(yaml).toContain("on_violation: block");
    const contract = parseContract(yaml);
    const blockRule = contract.rules.find((r) => r.id === "PII-001");
    expect(blockRule?.on_violation).toBe("block");
  });

  it("generates a valid rate limiting contract", () => {
    const yaml = gen.generate({
      template: "rate-limiting",
      params: { max_requests: 500, window: "PT30M", scope: "session" },
    });

    expect(yaml).toContain("500");
    expect(yaml).toContain("PT30M");
    expect(yaml).toContain("session_id");

    const contract = parseContract(yaml);
    expect(contract.rules.length).toBeGreaterThanOrEqual(1);
  });

  it("generates a valid content safety contract", () => {
    const yaml = gen.generate({
      template: "content-safety",
      params: { toxicity_threshold: 0.5, categories_to_block: ["hate_speech", "violence"] },
    });

    expect(yaml).toContain("0.5");
    expect(yaml).toContain("hate_speech");

    const contract = parseContract(yaml);
    expect(contract.rules.length).toBeGreaterThanOrEqual(2);
  });

  it("generates a valid access control contract", () => {
    const yaml = gen.generate({
      template: "access-control",
      params: { required_roles: ["admin", "editor"], require_auth: true },
    });

    expect(yaml).toContain("AUTH-001");
    expect(yaml).toContain("AUTH-002");

    const contract = parseContract(yaml);
    expect(contract.rules.length).toBe(2);
  });

  it("generates a valid model governance contract", () => {
    const yaml = gen.generate({
      template: "model-governance",
      params: { allowed_models: ["gpt-4", "claude-3-opus"], provider: "any" },
    });

    expect(yaml).toContain("gpt-4");
    expect(yaml).toContain("claude-3-opus");
    expect(yaml).toContain("model_bindings");

    const contract = parseContract(yaml);
    expect(contract.rules.length).toBeGreaterThanOrEqual(1);
    expect(contract.model_bindings).toBeDefined();
    expect(contract.model_bindings!.length).toBe(2);
  });

  it("generates a valid compliance baseline contract", () => {
    const yaml = gen.generate({
      template: "compliance-baseline",
      params: { frameworks: ["soc2", "gdpr"], retention_period: "P730D" },
    });

    expect(yaml).toContain("P730D");
    expect(yaml).toContain("soc2");
    expect(yaml).toContain("gdpr");

    const contract = parseContract(yaml);
    expect(contract.rules.length).toBeGreaterThanOrEqual(3);
  });

  it("throws on unknown template", () => {
    expect(() =>
      gen.generate({ template: "nonexistent", params: {} }),
    ).toThrow('Unknown template: "nonexistent"');
  });

  it("throws on missing required parameter", () => {
    expect(() =>
      gen.generate({ template: "rate-limiting", params: {} }),
    ).toThrow('Missing required parameter "max_requests"');
  });

  it("applies default parameter values", () => {
    const yaml = gen.generate({
      template: "rate-limiting",
      params: { max_requests: 100 },
    });

    // Default window is PT1H
    expect(yaml).toContain("PT1H");
    // Default scope is user
    expect(yaml).toContain("user_id");
  });

  it("uses custom metadata when provided", () => {
    const yaml = gen.generate({
      template: "pii-protection",
      params: {},
      metadata: {
        name: "Custom PII Policy",
        version: "2.0.0",
        author: "Custom Team",
        description: "Custom description",
        effective_date: "2026-06-01",
      },
    });

    expect(yaml).toContain("Custom PII Policy");
    expect(yaml).toContain("2.0.0");
    expect(yaml).toContain("Custom Team");
    expect(yaml).toContain("2026-06-01");
  });
});
