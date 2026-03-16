import YAML from "yaml";
import Ajv from "ajv";
import { TrustContract, PolicyRule, PolicyConditionExpr } from "../types";
import { trustContractSchema } from "./schema";
import type { ContractRegistry } from "./registry";

const ajv = new Ajv({ allErrors: true, strict: false });
const validate = ajv.compile(trustContractSchema);

export class ContractParseError extends Error {
  constructor(
    message: string,
    public readonly errors: string[],
  ) {
    super(message);
    this.name = "ContractParseError";
  }
}

/**
 * Parse a YAML or JSON string into a validated TrustContract.
 */
export function parseContract(source: string): TrustContract {
  let raw: unknown;
  try {
    raw = YAML.parse(source);
  } catch {
    // Fallback to JSON
    try {
      raw = JSON.parse(source);
    } catch {
      throw new ContractParseError("Source is neither valid YAML nor JSON", [
        "Failed to parse as YAML or JSON",
      ]);
    }
  }

  const valid = validate(raw);
  if (!valid) {
    const messages = (validate.errors ?? []).map(
      (e) => `${e.instancePath || "/"}: ${e.message}`,
    );
    throw new ContractParseError(
      `Trust contract validation failed with ${messages.length} error(s)`,
      messages,
    );
  }

  return raw as TrustContract;
}

/**
 * Serialize a TrustContract back to a pretty YAML string.
 */
export function serializeContract(contract: TrustContract): string {
  return YAML.stringify(contract, { indent: 2, lineWidth: 120 });
}

/**
 * Generate a plain-language summary from a trust contract.
 */
export function summarizeContract(contract: TrustContract): string {
  const { metadata, data_governance, rules } = contract;
  const lines: string[] = [
    `Trust Contract: "${metadata.name}" v${metadata.version}`,
    `Author: ${metadata.author}`,
    `Description: ${metadata.description}`,
    `Effective: ${metadata.effective_date}`,
    "",
    "Data Governance:",
    `  • Allowed input data classes: ${data_governance.allowed_input_classes.join(", ")}`,
    `  • Allowed output data classes: ${data_governance.allowed_output_classes.join(", ")}`,
    `  • Retention period: ${data_governance.retention_period}`,
    `  • Cross-border transfer: ${data_governance.cross_border_transfer ? "Permitted" : "Prohibited"}`,
    "",
    `Policy Rules (${rules.length}):`,
  ];

  for (const rule of rules) {
    const actions = Array.isArray(rule.action)
      ? rule.action.join(", ")
      : rule.action;
    lines.push(`  [${rule.on_violation.toUpperCase()}] ${rule.id}: ${rule.description}`);
    lines.push(`    Actions: ${actions}`);
    for (const cond of rule.conditions) {
      renderCondition(cond, lines, 4);
    }
    if (rule.obligations?.length) {
      lines.push(`    Obligations: ${rule.obligations.map((o) => o.type).join(", ")}`);
    }
  }

  return lines.join("\n");
}

function renderCondition(
  expr: PolicyConditionExpr,
  lines: string[],
  indent: number,
): void {
  const pad = " ".repeat(indent);

  if ("field" in expr) {
    lines.push(`${pad}Condition: ${expr.field} ${expr.operator} ${JSON.stringify(expr.value)}`);
    return;
  }

  if ("all" in expr) {
    lines.push(`${pad}ALL of:`);
    for (const child of expr.all) {
      renderCondition(child, lines, indent + 2);
    }
    return;
  }

  if ("any" in expr) {
    lines.push(`${pad}ANY of:`);
    for (const child of expr.any) {
      renderCondition(child, lines, indent + 2);
    }
    return;
  }

  if ("not" in expr) {
    lines.push(`${pad}NOT:`);
    renderCondition(expr.not, lines, indent + 2);
  }
}

/**
 * Resolve contract inheritance by merging rules from a parent contract.
 *
 * - Child rules are added to parent rules
 * - `override_rules` replace parent rules with matching IDs
 * - Circular inheritance is detected and throws
 *
 * @param contract The child contract with an `extends` field
 * @param registry The contract registry to look up the parent
 * @param seen Set of contract names in the inheritance chain (for cycle detection)
 * @returns A new TrustContract with merged rules (does not mutate inputs)
 */
export function resolveInheritance(
  contract: TrustContract,
  registry: ContractRegistry,
  seen: Set<string> = new Set(),
): TrustContract {
  if (!contract.extends) return contract;

  const parentName = contract.extends;

  // Cycle detection
  if (seen.has(contract.metadata.name)) {
    throw new ContractParseError(
      `Circular inheritance detected: ${[...seen, contract.metadata.name].join(" -> ")}`,
      [`Contract "${contract.metadata.name}" creates a circular inheritance chain`],
    );
  }
  seen.add(contract.metadata.name);

  // Look up parent
  const parent = registry.getActive(parentName);
  if (!parent) {
    throw new ContractParseError(
      `Parent contract "${parentName}" not found in registry`,
      [`Contract "${contract.metadata.name}" extends "${parentName}" but it is not registered or active`],
    );
  }

  // Recursively resolve parent's own inheritance
  const resolvedParent = resolveInheritance(parent, registry, seen);

  // Build merged rule list:
  // 1. Start with parent rules
  // 2. Apply overrides from child
  // 3. Add child's own rules
  const overrideMap = new Map<string, PolicyRule>();
  for (const rule of contract.override_rules ?? []) {
    overrideMap.set(rule.id, rule);
  }

  const mergedRules: PolicyRule[] = [];

  // Parent rules (with overrides applied)
  for (const parentRule of resolvedParent.rules) {
    if (overrideMap.has(parentRule.id)) {
      mergedRules.push(overrideMap.get(parentRule.id)!);
    } else {
      mergedRules.push(parentRule);
    }
  }

  // Child's own rules (that aren't overrides of parent rules)
  const parentRuleIds = new Set(resolvedParent.rules.map((r) => r.id));
  for (const childRule of contract.rules) {
    if (!parentRuleIds.has(childRule.id)) {
      mergedRules.push(childRule);
    } else {
      // If child defines a rule with same ID as parent, treat as override
      const idx = mergedRules.findIndex((r) => r.id === childRule.id);
      if (idx >= 0) mergedRules[idx] = childRule;
    }
  }

  return {
    ...contract,
    rules: mergedRules,
    extends: undefined, // Inheritance resolved
    override_rules: undefined,
  };
}
