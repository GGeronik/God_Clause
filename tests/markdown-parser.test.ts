import { describe, it, expect } from "vitest";
import { parseMarkdownContract } from "../src/contracts/markdown-parser";

const validYAML = `
schema_version: "1.0"
metadata:
  name: Test Contract
  version: "1.0.0"
  author: Test
  description: A test contract
  effective_date: "2025-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: T-001
    description: Block unsafe output
    action: generate
    conditions:
      - field: output.safe
        operator: equals
        value: true
    on_violation: block
    tags: [safety]
`.trim();

describe("Markdown Contract Parser", () => {
  it("extracts a YAML contract from a markdown document", () => {
    const md = `# My Policy

This policy governs AI safety.

\`\`\`yaml
${validYAML}
\`\`\`

## Notes

Some additional notes here.`;

    const result = parseMarkdownContract(md);
    expect(result.contract.metadata.name).toBe("Test Contract");
    expect(result.contract.rules).toHaveLength(1);
    expect(result.contract.rules[0].id).toBe("T-001");
  });

  it("preserves prose sections", () => {
    const md = `# Header

Introduction paragraph.

\`\`\`yaml
${validYAML}
\`\`\`

Footer paragraph.`;

    const result = parseMarkdownContract(md);
    expect(result.prose).toContain("Header");
    expect(result.prose).toContain("Introduction paragraph");
    expect(result.prose).toContain("Footer paragraph");
  });

  it("identifies section types correctly", () => {
    const md = `# Intro

\`\`\`yaml
${validYAML}
\`\`\`

\`\`\`yaml
some: other
yaml: content
\`\`\`

Closing text.`;

    const result = parseMarkdownContract(md);
    const types = result.sections.map((s) => s.type);
    expect(types).toContain("prose");
    expect(types).toContain("contract");
    expect(types).toContain("example");
  });

  it("uses the first valid contract block", () => {
    const secondYAML = validYAML.replace("Test Contract", "Second Contract");
    const md = `
\`\`\`yaml
${validYAML}
\`\`\`

\`\`\`yaml
${secondYAML}
\`\`\`
`;

    const result = parseMarkdownContract(md);
    expect(result.contract.metadata.name).toBe("Test Contract");
  });

  it("skips invalid YAML blocks and uses the first valid one", () => {
    const md = `
\`\`\`yaml
this is not: [a valid contract
\`\`\`

\`\`\`yaml
${validYAML}
\`\`\`
`;

    const result = parseMarkdownContract(md);
    expect(result.contract.metadata.name).toBe("Test Contract");
  });

  it("throws when no valid contract found", () => {
    const md = `# Just prose

No code blocks here at all.`;

    expect(() => parseMarkdownContract(md)).toThrow("No valid trust contract found");
  });

  it("throws with detail when code blocks exist but are invalid", () => {
    const md = `
\`\`\`yaml
invalid: yaml: [broken
\`\`\`
`;

    expect(() => parseMarkdownContract(md)).toThrow("No valid trust contract found");
  });

  it("handles JSON code blocks", () => {
    const jsonContract = JSON.stringify({
      schema_version: "1.0",
      metadata: {
        name: "JSON Contract",
        version: "1.0.0",
        author: "Test",
        description: "A JSON contract",
        effective_date: "2025-01-01",
      },
      data_governance: {
        allowed_input_classes: ["public"],
        allowed_output_classes: ["public"],
        retention_period: "P30D",
        cross_border_transfer: false,
      },
      rules: [
        {
          id: "J-001",
          description: "JSON rule",
          action: "generate",
          conditions: [{ field: "output.x", operator: "equals", value: true }],
          on_violation: "block",
        },
      ],
    }, null, 2);

    const md = `# JSON Policy

\`\`\`json
${jsonContract}
\`\`\`
`;

    const result = parseMarkdownContract(md);
    expect(result.contract.metadata.name).toBe("JSON Contract");
  });

  it("handles god-clause fenced blocks", () => {
    const md = `
\`\`\`god-clause
${validYAML}
\`\`\`
`;

    const result = parseMarkdownContract(md);
    expect(result.contract.metadata.name).toBe("Test Contract");
  });

  it("tracks line numbers for sections", () => {
    const md = `Line 1
Line 2
\`\`\`yaml
${validYAML}
\`\`\`
Last line`;

    const result = parseMarkdownContract(md);
    // Should have prose, contract, prose sections
    expect(result.sections.length).toBeGreaterThanOrEqual(2);

    const contractSection = result.sections.find((s) => s.type === "contract");
    expect(contractSection).toBeDefined();
    expect(contractSection!.line_start).toBeGreaterThan(1);
  });

  it("handles empty document", () => {
    expect(() => parseMarkdownContract("")).toThrow("No valid trust contract found");
  });

  it("handles document with only prose", () => {
    expect(() => parseMarkdownContract("# Title\n\nJust text.")).toThrow(
      "No valid trust contract found",
    );
  });
});
