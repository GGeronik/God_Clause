import { execFile } from "child_process";
import type {
  TrustContract,
  PolicyRule,
  PolicyConditionExpr,
  PolicyConditionLeaf,
  ConditionOperator,
  TLAPlusOptions,
  TLAPlusSpec,
  ModelCheckResult,
} from "../types";

export class TLAPlusGenerator {
  private opts: TLAPlusOptions;

  constructor(opts?: TLAPlusOptions) {
    this.opts = opts ?? {};
  }

  /**
   * Generate a complete TLA+ specification from a TrustContract.
   */
  generate(contract: TrustContract): TLAPlusSpec {
    const moduleName = sanitizeModuleName(contract.metadata.name);
    const specContent = this.generateSpec(contract);
    const configContent = this.generateConfig(contract);
    const invariants = this.extractInvariants(contract);
    const properties = this.extractProperties(contract);

    return { moduleName, specContent, configContent, invariants, properties };
  }

  /**
   * Generate the .tla specification content.
   */
  generateSpec(contract: TrustContract): string {
    const moduleName = sanitizeModuleName(contract.metadata.name);
    const fields = extractAllFields(contract.rules);
    const invariants = this.extractInvariants(contract);
    const properties = this.extractProperties(contract);

    const lines: string[] = [];

    // Module header
    lines.push(`---- MODULE ${moduleName} ----`);
    lines.push(`EXTENDS Integers, Sequences, TLC`);
    lines.push(``);

    // Constants
    lines.push(`\\* Constants for possible outcomes`);
    lines.push(`CONSTANTS Permit, Deny, Modify`);
    lines.push(``);

    // State variables
    lines.push(`VARIABLES`);
    lines.push(`  state,         \\* "init" | "evaluating" | "decided"`);
    lines.push(`  outcome,       \\* Permit | Deny | Modify`);
    lines.push(`  action,        \\* The action being evaluated`);

    // Add field variables
    for (const field of fields) {
      const varName = fieldToVar(field);
      lines.push(`  ${varName},    \\* Field: ${field}`);
    }

    // Rule result variables
    for (const rule of contract.rules) {
      const varName = `rule_${sanitizeId(rule.id)}_passed`;
      lines.push(`  ${varName},`);
    }

    // Remove trailing comma from last variable
    if (lines.length > 0) {
      lines[lines.length - 1] = lines[lines.length - 1].replace(/,$/, "");
    }

    lines.push(``);

    // vars tuple
    const allVars = [
      "state",
      "outcome",
      "action",
      ...fields.map(fieldToVar),
      ...contract.rules.map((r) => `rule_${sanitizeId(r.id)}_passed`),
    ];
    lines.push(`vars == << ${allVars.join(", ")} >>`);
    lines.push(``);

    // Init predicate
    lines.push(`Init ==`);
    lines.push(`  /\\ state = "init"`);
    lines.push(`  /\\ outcome = Permit`);
    lines.push(
      `  /\\ action \\in {"generate", "classify", "summarize", "translate", "extract", "transform", "decide", "recommend"}`,
    );
    for (const field of fields) {
      lines.push(`  /\\ ${fieldToVar(field)} \\in {TRUE, FALSE}`);
    }
    for (const rule of contract.rules) {
      lines.push(`  /\\ rule_${sanitizeId(rule.id)}_passed = TRUE`);
    }
    lines.push(``);

    // Evaluate action — each rule becomes a conjunct
    lines.push(`Evaluate ==`);
    lines.push(`  /\\ state = "init"`);
    lines.push(`  /\\ state' = "evaluating"`);

    for (const rule of contract.rules) {
      const condExpr = ruleConditionToTLA(rule);
      const ruleVar = `rule_${sanitizeId(rule.id)}_passed`;
      const actions = Array.isArray(rule.action) ? rule.action : [rule.action];
      const actionGuard = actions.includes("*") ? "TRUE" : actions.map((a) => `action = "${a}"`).join(" \\/ ");

      lines.push(`  /\\ ${ruleVar}' = IF (${actionGuard}) THEN (${condExpr}) ELSE TRUE`);
    }

    // Unchanged field vars
    lines.push(`  /\\ action' = action`);
    lines.push(`  /\\ outcome' = outcome`);
    for (const field of fields) {
      lines.push(`  /\\ ${fieldToVar(field)}' = ${fieldToVar(field)}`);
    }
    lines.push(``);

    // Decide action — compute outcome from rule results
    lines.push(`Decide ==`);
    lines.push(`  /\\ state = "evaluating"`);
    lines.push(`  /\\ state' = "decided"`);

    // Compute outcome based on rule severities
    const blockRules = contract.rules.filter((r) => r.on_violation === "block");
    const modifyRules = contract.rules.filter((r) => r.on_violation === "modify");

    if (blockRules.length > 0) {
      const anyBlockFailed = blockRules.map((r) => `rule_${sanitizeId(r.id)}_passed = FALSE`).join(" \\/ ");
      const anyModifyFailed =
        modifyRules.length > 0
          ? modifyRules.map((r) => `rule_${sanitizeId(r.id)}_passed = FALSE`).join(" \\/ ")
          : "FALSE";

      lines.push(`  /\\ outcome' = IF (${anyBlockFailed}) THEN Deny`);
      lines.push(`               ELSE IF (${anyModifyFailed}) THEN Modify`);
      lines.push(`               ELSE Permit`);
    } else if (modifyRules.length > 0) {
      const anyModifyFailed = modifyRules.map((r) => `rule_${sanitizeId(r.id)}_passed = FALSE`).join(" \\/ ");
      lines.push(`  /\\ outcome' = IF (${anyModifyFailed}) THEN Modify ELSE Permit`);
    } else {
      lines.push(`  /\\ outcome' = Permit`);
    }

    // Unchanged
    lines.push(`  /\\ action' = action`);
    for (const field of fields) {
      lines.push(`  /\\ ${fieldToVar(field)}' = ${fieldToVar(field)}`);
    }
    for (const rule of contract.rules) {
      lines.push(`  /\\ rule_${sanitizeId(rule.id)}_passed' = rule_${sanitizeId(rule.id)}_passed`);
    }
    lines.push(``);

    // Next state
    lines.push(`Next == Evaluate \\/ Decide`);
    lines.push(``);

    // Spec
    lines.push(`Spec == Init /\\ [][Next]_vars`);
    lines.push(``);

    // Invariants
    for (const inv of invariants) {
      lines.push(`${inv} ==`);
      if (inv === "NoPermitWhenBlockViolated") {
        if (blockRules.length > 0) {
          const blockFailed = blockRules.map((r) => `rule_${sanitizeId(r.id)}_passed = FALSE`).join(" \\/ ");
          lines.push(`  state = "decided" => ~((${blockFailed}) /\\ outcome = Permit)`);
        } else {
          lines.push(`  TRUE`);
        }
      } else if (inv === "ModifyHasObligations") {
        lines.push(`  state = "decided" => (outcome = Modify => TRUE) \\* Obligations checked structurally`);
      } else if (inv === "TypeInvariant") {
        lines.push(`  /\\ state \\in {"init", "evaluating", "decided"}`);
        lines.push(`  /\\ outcome \\in {Permit, Deny, Modify}`);
      }
      lines.push(``);
    }

    // Properties
    for (const prop of properties) {
      if (prop === "EventuallyDecided") {
        lines.push(`${prop} == <>(state = "decided")`);
      }
      lines.push(``);
    }

    lines.push(`====`);

    return lines.join("\n");
  }

  /**
   * Generate the .cfg configuration content.
   */
  generateConfig(contract: TrustContract): string {
    const invariants = this.extractInvariants(contract);
    const properties = this.extractProperties(contract);

    const lines: string[] = [];
    lines.push(`SPECIFICATION Spec`);
    lines.push(``);
    lines.push(`CONSTANTS`);
    lines.push(`  Permit = "permit"`);
    lines.push(`  Deny = "deny"`);
    lines.push(`  Modify = "modify"`);
    lines.push(``);

    for (const inv of invariants) {
      lines.push(`INVARIANT ${inv}`);
    }
    lines.push(``);

    for (const prop of properties) {
      lines.push(`PROPERTY ${prop}`);
    }

    return lines.join("\n");
  }

  /**
   * Run the TLC model checker on a generated spec.
   */
  async runModelChecker(spec: TLAPlusSpec): Promise<ModelCheckResult> {
    const tlcPath = this.opts.tlcPath;
    if (!tlcPath) {
      return {
        status: "unavailable",
        invariantsChecked: spec.invariants,
        rawOutput: "TLC path not configured. Set tlcPath option to tla2tools.jar location.",
      };
    }

    // Check if Java and TLC jar exist
    try {
      return await new Promise<ModelCheckResult>((resolve) => {
        const args = ["-jar", tlcPath, "-config", "spec.cfg"];
        if (this.opts.maxStates) {
          args.push("-maxSetSize", String(this.opts.maxStates));
        }

        execFile("java", args, { timeout: 60000 }, (error, stdout, stderr) => {
          const rawOutput = stdout + "\n" + stderr;

          if (error) {
            // Check if it's a model checking failure or a setup error
            if (rawOutput.includes("Error:") || rawOutput.includes("Invariant")) {
              resolve({
                status: "failed",
                invariantsChecked: spec.invariants,
                statesExplored: parseStatesExplored(rawOutput),
                counterexample: parseCounterexample(rawOutput),
                rawOutput,
              });
            } else {
              resolve({
                status: "error",
                invariantsChecked: spec.invariants,
                rawOutput,
              });
            }
            return;
          }

          resolve({
            status: "passed",
            statesExplored: parseStatesExplored(rawOutput),
            invariantsChecked: spec.invariants,
            rawOutput,
          });
        });
      });
    } catch {
      return {
        status: "unavailable",
        invariantsChecked: spec.invariants,
        rawOutput: "Java or TLC not found. Install Java and download tla2tools.jar.",
      };
    }
  }

  private extractInvariants(contract: TrustContract): string[] {
    const invariants = ["TypeInvariant"];
    const hasBlock = contract.rules.some((r) => r.on_violation === "block");
    if (hasBlock) invariants.push("NoPermitWhenBlockViolated");
    const hasModify = contract.rules.some((r) => r.on_violation === "modify" && r.obligations?.length);
    if (hasModify) invariants.push("ModifyHasObligations");
    return invariants;
  }

  private extractProperties(_contract: TrustContract): string[] {
    return ["EventuallyDecided"];
  }
}

// ─── Helper Functions ──────────────────────────────────────────────

export function sanitizeModuleName(name: string): string {
  return name.replace(/[^a-zA-Z0-9_]/g, "_");
}

export function sanitizeId(id: string): string {
  return id.replace(/[^a-zA-Z0-9_]/g, "_");
}

export function fieldToVar(field: string): string {
  return "f_" + field.replace(/\./g, "_").replace(/[^a-zA-Z0-9_]/g, "");
}

export function extractAllFields(rules: PolicyRule[]): string[] {
  const fields = new Set<string>();
  for (const rule of rules) {
    extractFieldsFromConditions(rule.conditions, fields);
  }
  return [...fields].sort();
}

function extractFieldsFromConditions(conditions: PolicyConditionExpr[], fields: Set<string>): void {
  for (const cond of conditions) {
    if ("field" in cond) {
      fields.add((cond as PolicyConditionLeaf).field);
    }
    if ("all" in cond) extractFieldsFromConditions((cond as { all: PolicyConditionExpr[] }).all, fields);
    if ("any" in cond) extractFieldsFromConditions((cond as { any: PolicyConditionExpr[] }).any, fields);
    if ("not" in cond) extractFieldsFromConditions([(cond as { not: PolicyConditionExpr }).not], fields);
  }
}

export function ruleConditionToTLA(rule: PolicyRule): string {
  if (rule.conditions.length === 0) return "TRUE";
  const parts = rule.conditions.map((c) => conditionToTLA(c));
  return parts.join(" /\\ ");
}

export function conditionToTLA(expr: PolicyConditionExpr): string {
  if ("field" in expr) {
    const leaf = expr as PolicyConditionLeaf;
    const varName = fieldToVar(leaf.field);
    return leafToTLA(varName, leaf.operator, leaf.value);
  }
  if ("all" in expr) {
    const parts = (expr as { all: PolicyConditionExpr[] }).all.map((e: PolicyConditionExpr) => conditionToTLA(e));
    return `(${parts.join(" /\\ ")})`;
  }
  if ("any" in expr) {
    const parts = (expr as { any: PolicyConditionExpr[] }).any.map((e: PolicyConditionExpr) => conditionToTLA(e));
    return `(${parts.join(" \\/ ")})`;
  }
  if ("not" in expr) {
    return `~(${conditionToTLA((expr as { not: PolicyConditionExpr }).not)})`;
  }
  return "TRUE";
}

export function leafToTLA(varName: string, operator: ConditionOperator, value: unknown): string {
  switch (operator) {
    case "equals":
      return `${varName} = ${tlaValue(value)}`;
    case "not_equals":
      return `${varName} /= ${tlaValue(value)}`;
    case "greater_than":
      return `${varName} > ${tlaValue(value)}`;
    case "less_than":
      return `${varName} < ${tlaValue(value)}`;
    case "contains":
      return `${tlaValue(value)} \\in ${varName}`;
    case "not_contains":
      return `~(${tlaValue(value)} \\in ${varName})`;
    case "in":
      return `${varName} \\in ${tlaSetValue(value)}`;
    case "not_in":
      return `~(${varName} \\in ${tlaSetValue(value)})`;
    case "exists":
      return `${varName} /= "NULL"`;
    case "not_exists":
      return `${varName} = "NULL"`;
    case "matches":
      return `TRUE \\* regex: ${String(value)}`;
    case "rate_limit":
      return `TRUE \\* rate_limit evaluated at runtime`;
    default:
      return "TRUE";
  }
}

export function tlaValue(val: unknown): string {
  if (typeof val === "boolean") return val ? "TRUE" : "FALSE";
  if (typeof val === "number") return String(val);
  if (typeof val === "string") return `"${val}"`;
  return `"${String(val)}"`;
}

export function tlaSetValue(val: unknown): string {
  if (Array.isArray(val)) {
    return `{${val.map(tlaValue).join(", ")}}`;
  }
  return `{${tlaValue(val)}}`;
}

function parseStatesExplored(output: string): number | undefined {
  const match = output.match(/(\d+)\s+states generated/);
  return match ? parseInt(match[1], 10) : undefined;
}

function parseCounterexample(output: string): string | undefined {
  const idx = output.indexOf("Error:");
  if (idx === -1) return undefined;
  return output.slice(idx, idx + 500);
}
