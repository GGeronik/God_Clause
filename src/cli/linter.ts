import { TrustContract, PolicyRule, PolicyConditionExpr, PolicyConditionLeaf } from "../types";

export type LintSeverity = "error" | "warning";

export interface LintResult {
  rule: string;
  severity: LintSeverity;
  message: string;
  ruleId?: string;
}

/**
 * Lint a trust contract for best practices and common mistakes.
 * Returns an array of findings (errors and warnings).
 */
export function lintContract(contract: TrustContract): LintResult[] {
  const results: LintResult[] = [];

  // Check for data_governance section
  if (!contract.data_governance) {
    results.push({
      rule: "data-governance-required",
      severity: "warning",
      message: "Contract is missing data_governance section",
    });
  }

  // Check for review_date
  if (!contract.metadata.review_date) {
    results.push({
      rule: "review-date-recommended",
      severity: "warning",
      message: "Contract has no review_date — consider setting a review schedule",
    });
  }

  // Check for stakeholders
  if (!contract.metadata.stakeholders?.length) {
    results.push({
      rule: "stakeholders-recommended",
      severity: "warning",
      message: "Contract has no stakeholders listed",
    });
  }

  const ruleIds = new Set<string>();
  for (const rule of contract.rules) {
    // Duplicate rule IDs
    if (ruleIds.has(rule.id)) {
      results.push({
        rule: "duplicate-rule-id",
        severity: "error",
        message: `Duplicate rule ID: ${rule.id}`,
        ruleId: rule.id,
      });
    }
    ruleIds.add(rule.id);

    // Missing tags
    if (!rule.tags?.length) {
      results.push({
        rule: "missing-tags",
        severity: "warning",
        message: `Rule ${rule.id} has no tags — tags enable filtering and analytics`,
        ruleId: rule.id,
      });
    }

    // Block severity with wildcard action
    const actions = Array.isArray(rule.action) ? rule.action : [rule.action];
    if (actions.includes("*") && rule.on_violation === "block") {
      results.push({
        rule: "wildcard-block-dangerous",
        severity: "warning",
        message: `Rule ${rule.id} blocks all actions ("*") — this may be overly broad`,
        ruleId: rule.id,
      });
    }

    // Modify severity without obligations
    if (rule.on_violation === "modify" && (!rule.obligations || rule.obligations.length === 0)) {
      results.push({
        rule: "modify-needs-obligations",
        severity: "error",
        message: `Rule ${rule.id} has "modify" severity but no obligations — modify decisions must specify what to do`,
        ruleId: rule.id,
      });
    }

    // Check rate limit windows
    for (const cond of rule.conditions) {
      if ("field" in cond && cond.operator === "rate_limit") {
        const val = cond.value as { max?: number; window?: string };
        if (val.window) {
          const days = parseRoughDays(val.window);
          if (days > 30) {
            results.push({
              rule: "rate-limit-window-too-large",
              severity: "warning",
              message: `Rule ${rule.id} has a rate limit window of "${val.window}" (>${days} days) — consider a shorter window`,
              ruleId: rule.id,
            });
          }
        }
        if (val.max !== undefined && val.max <= 0) {
          results.push({
            rule: "rate-limit-max-invalid",
            severity: "error",
            message: `Rule ${rule.id} has rate_limit max=${val.max} — must be positive`,
            ruleId: rule.id,
          });
        }
      }
    }

    // No conditions
    if (rule.conditions.length === 0) {
      results.push({
        rule: "empty-conditions",
        severity: "warning",
        message: `Rule ${rule.id} has no conditions — it will never trigger a violation`,
        ruleId: rule.id,
      });
    }
  }

  // No rules at all
  if (contract.rules.length === 0) {
    results.push({
      rule: "no-rules",
      severity: "warning",
      message: "Contract has no rules defined",
    });
  }

  // ─── Extended Lint Rules ────────────────────────────────────────────

  // Rule shadowing: detect rules completely shadowed by earlier block rules
  lintRuleShadowing(contract.rules, results);

  // Missing deny for hazard class
  lintMissingDenyForHazard(contract.rules, results);

  // Model binding unused
  lintModelBindingUnused(contract, results);

  // MCP permission overlap
  lintMCPPermissionOverlap(contract, results);

  // Obligation without standard handler
  lintObligationTypes(contract.rules, results);

  // Missing required evidence
  lintMissingRequiredEvidence(contract.rules, results);

  // Rule unreachable (conflicting conditions)
  lintUnreachableRules(contract.rules, results);

  return results;
}

// ─── Extended Lint Helpers ──────────────────────────────────────────

const STANDARD_OBLIGATION_TYPES = new Set([
  "redact_pii",
  "append_notice",
  "append_attribution",
  "require_review",
  "add_disclaimer",
  "truncate",
  "filter",
  "log_extra",
  "notify",
]);

/** Detect rules shadowed by earlier block rules with the same or broader action scope. */
function lintRuleShadowing(rules: PolicyRule[], results: LintResult[]): void {
  const blockRules: PolicyRule[] = [];

  for (const rule of rules) {
    const ruleActions = new Set(Array.isArray(rule.action) ? rule.action : [rule.action]);

    // Check if this rule is shadowed by any earlier block rule
    for (const blocker of blockRules) {
      const blockerActions = new Set(Array.isArray(blocker.action) ? blocker.action : [blocker.action]);

      // Wildcard blocks shadow everything; same action blocks shadow same action
      const isShadowed =
        blockerActions.has("*") || [...ruleActions].every((a) => blockerActions.has(a) || blockerActions.has("*"));

      if (isShadowed && rule.on_violation !== "block") {
        results.push({
          rule: "rule-shadowed",
          severity: "warning",
          message: `Rule ${rule.id} may be shadowed by earlier block rule ${blocker.id} — if ${blocker.id} fires, ${rule.id} won't matter`,
          ruleId: rule.id,
        });
        break;
      }
    }

    if (rule.on_violation === "block") {
      blockRules.push(rule);
    }
  }
}

/** Warn if a hazard_class is defined but has no block-severity rule. */
function lintMissingDenyForHazard(rules: PolicyRule[], results: LintResult[]): void {
  const hazardClasses = new Set<string>();
  const blockedHazards = new Set<string>();

  for (const rule of rules) {
    if (rule.hazard_class) {
      hazardClasses.add(rule.hazard_class);
      if (rule.on_violation === "block") {
        blockedHazards.add(rule.hazard_class);
      }
    }
  }

  for (const hazard of hazardClasses) {
    if (!blockedHazards.has(hazard)) {
      results.push({
        rule: "missing-deny-for-hazard",
        severity: "warning",
        message: `Hazard class "${hazard}" has no block-severity rule — consider adding one`,
      });
    }
  }
}

/** Warn if model_bindings are defined but no rules reference model metadata. */
function lintModelBindingUnused(contract: TrustContract, results: LintResult[]): void {
  if (!contract.model_bindings?.length) return;

  const referencesModel = contract.rules.some((rule) => conditionsReferenceField(rule.conditions, "metadata.model"));

  if (!referencesModel) {
    results.push({
      rule: "model-binding-unused",
      severity: "warning",
      message: `Contract defines ${contract.model_bindings.length} model binding(s) but no rules reference model metadata fields`,
    });
  }
}

/** Detect overlapping glob patterns in MCP permissions. */
function lintMCPPermissionOverlap(contract: TrustContract, results: LintResult[]): void {
  if (!contract.mcp_permissions || contract.mcp_permissions.length < 2) return;

  for (let i = 0; i < contract.mcp_permissions.length; i++) {
    for (let j = i + 1; j < contract.mcp_permissions.length; j++) {
      const a = contract.mcp_permissions[i].tool_pattern;
      const b = contract.mcp_permissions[j].tool_pattern;

      if (patternsOverlap(a, b)) {
        results.push({
          rule: "mcp-permission-overlap",
          severity: "warning",
          message: `MCP permissions "${a}" and "${b}" have overlapping patterns — first-match-wins, so "${b}" may be unreachable`,
        });
      }
    }
  }
}

/** Warn if obligation types are non-standard. */
function lintObligationTypes(rules: PolicyRule[], results: LintResult[]): void {
  for (const rule of rules) {
    if (!rule.obligations) continue;
    for (const obl of rule.obligations) {
      if (!STANDARD_OBLIGATION_TYPES.has(obl.type)) {
        results.push({
          rule: "obligation-without-handler",
          severity: "warning",
          message: `Rule ${rule.id} uses non-standard obligation type "${obl.type}" — ensure a handler is registered`,
          ruleId: rule.id,
        });
      }
    }
  }
}

/** Warn if required_evidence is specified but the rule can't collect it. */
function lintMissingRequiredEvidence(rules: PolicyRule[], results: LintResult[]): void {
  for (const rule of rules) {
    if (!rule.required_evidence?.length) continue;

    for (const evidence of rule.required_evidence) {
      // "human_review" needs a modify obligation with require_review
      if (evidence === "human_review") {
        const hasReviewObl = rule.obligations?.some((o) => o.type === "require_review");
        if (!hasReviewObl && rule.on_violation !== "modify") {
          results.push({
            rule: "missing-required-evidence",
            severity: "warning",
            message: `Rule ${rule.id} requires "${evidence}" evidence but has no require_review obligation`,
            ruleId: rule.id,
          });
        }
      }
    }
  }
}

/** Detect rules with conflicting leaf conditions that can never be satisfied simultaneously. */
function lintUnreachableRules(rules: PolicyRule[], results: LintResult[]): void {
  for (const rule of rules) {
    const leafConditions = extractLeafConditions(rule.conditions);

    // Check for conflicting conditions on the same field
    const fieldConditions = new Map<string, PolicyConditionLeaf[]>();
    for (const leaf of leafConditions) {
      const existing = fieldConditions.get(leaf.field) || [];
      existing.push(leaf);
      fieldConditions.set(leaf.field, existing);
    }

    for (const [field, conds] of fieldConditions) {
      if (conds.length < 2) continue;

      // Check for equals + not_equals on same value
      const equals = conds.filter((c) => c.operator === "equals");
      const notEquals = conds.filter((c) => c.operator === "not_equals");

      for (const eq of equals) {
        for (const neq of notEquals) {
          if (JSON.stringify(eq.value) === JSON.stringify(neq.value)) {
            results.push({
              rule: "rule-unreachable",
              severity: "warning",
              message: `Rule ${rule.id} has conflicting conditions on "${field}": equals and not_equals with the same value — this rule can never fire`,
              ruleId: rule.id,
            });
            return; // One finding per rule is enough
          }
        }
      }

      // Check for greater_than + less_than creating impossible range
      const gt = conds.filter((c) => c.operator === "greater_than");
      const lt = conds.filter((c) => c.operator === "less_than");
      for (const g of gt) {
        for (const l of lt) {
          if (typeof g.value === "number" && typeof l.value === "number" && g.value >= l.value) {
            results.push({
              rule: "rule-unreachable",
              severity: "warning",
              message: `Rule ${rule.id} has impossible range on "${field}": greater_than ${g.value} AND less_than ${l.value}`,
              ruleId: rule.id,
            });
            return;
          }
        }
      }
    }
  }
}

/** Check if any condition in the tree references a field starting with the given prefix. */
function conditionsReferenceField(conditions: PolicyConditionExpr[], prefix: string): boolean {
  for (const cond of conditions) {
    if ("field" in cond) {
      if ((cond as PolicyConditionLeaf).field.startsWith(prefix)) return true;
    }
    if ("all" in cond) {
      if (conditionsReferenceField((cond as any).all, prefix)) return true;
    }
    if ("any" in cond) {
      if (conditionsReferenceField((cond as any).any, prefix)) return true;
    }
    if ("not" in cond) {
      if (conditionsReferenceField([(cond as any).not], prefix)) return true;
    }
  }
  return false;
}

/** Extract all leaf conditions from a condition expression tree. */
function extractLeafConditions(conditions: PolicyConditionExpr[]): PolicyConditionLeaf[] {
  const leaves: PolicyConditionLeaf[] = [];
  for (const cond of conditions) {
    if ("field" in cond) {
      leaves.push(cond as PolicyConditionLeaf);
    }
    if ("all" in cond) leaves.push(...extractLeafConditions((cond as any).all));
    if ("any" in cond) leaves.push(...extractLeafConditions((cond as any).any));
    if ("not" in cond) leaves.push(...extractLeafConditions([(cond as any).not]));
  }
  return leaves;
}

/** Check if two glob patterns could match the same tool name. */
function patternsOverlap(a: string, b: string): boolean {
  // If either is "*", they definitely overlap
  if (a === "*" || b === "*") return true;
  // If one contains *, it could match the other
  if (a.includes("*") && matchGlob(a, b.replace(/\*/g, "x"))) return true;
  if (b.includes("*") && matchGlob(b, a.replace(/\*/g, "x"))) return true;
  // Exact match
  return a === b;
}

/** Simple glob matching — * matches any sequence of characters. */
function matchGlob(pattern: string, text: string): boolean {
  const regex = new RegExp("^" + pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*") + "$");
  return regex.test(text);
}

/** Rough estimate of days from ISO 8601 duration for validation purposes. */
function parseRoughDays(duration: string): number {
  let days = 0;
  const dayMatch = duration.match(/(\d+)D/);
  if (dayMatch) days += parseInt(dayMatch[1], 10);
  const monthMatch = duration.match(/(\d+)M(?!.*T.*\dM)/);
  if (monthMatch) days += parseInt(monthMatch[1], 10) * 30;
  const yearMatch = duration.match(/(\d+)Y/);
  if (yearMatch) days += parseInt(yearMatch[1], 10) * 365;
  return days;
}
