import { describe, it, expect } from "vitest";
import { compilePattern } from "../src/engine/evaluator";
import { parseContract, ContractParseError } from "../src";

function contractWith(value: string): string {
  return JSON.stringify({
    schema_version: "1.0",
    metadata: { name: "P", version: "1.0.0", author: "T", description: "T", effective_date: "2026-01-01" },
    data_governance: {
      allowed_input_classes: ["public"],
      allowed_output_classes: ["public"],
      retention_period: "P30D",
      cross_border_transfer: false,
    },
    rules: [
      {
        id: "R-1",
        description: "t",
        action: "generate",
        conditions: [{ field: "input.prompt", operator: "matches", value }],
        on_violation: "block",
      },
    ],
  });
}

describe("matches patterns", () => {
  it("accepts a bare pattern and /pattern/flags", () => {
    expect(compilePattern("^abc").test("abcd")).toBe(true);
    expect(compilePattern("/abc/i").test("xABCx")).toBe(true);
    expect(compilePattern("/abc/").test("ABC")).toBe(false);
    expect(compilePattern("/^a.b$/s").test("a\nb")).toBe(true);
  });

  it("rejects unsupported flags at load time instead of matching the slashes literally", () => {
    expect(() => compilePattern("/abc/g")).toThrow(/Unsupported regex flags/);
    expect(() => parseContract(contractWith("/abc/gx"))).toThrow(ContractParseError);
    expect(() => parseContract(contractWith("/abc/i"))).not.toThrow();
  });
});
