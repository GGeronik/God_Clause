import type { ContractMetadata } from "../types";

/**
 * A P2T (Policy-to-Trust) template definition.
 */
export interface P2TTemplate {
  /** Template identifier. */
  id: string;
  /** Human-readable name. */
  name: string;
  /** Description of what this template generates. */
  description: string;
  /** Parameters accepted by the template. */
  params: P2TParam[];
}

export interface P2TParam {
  name: string;
  type: "string" | "number" | "boolean" | "string[]";
  required: boolean;
  default?: unknown;
  description?: string;
}

/**
 * Input for P2T contract generation.
 */
export interface P2TInput {
  /** Template ID to use. */
  template: string;
  /** Template-specific parameters. */
  params: Record<string, unknown>;
  /** Optional metadata overrides. */
  metadata?: Partial<ContractMetadata>;
}

// ─── Built-in Templates ──────────────────────────────────────────────

const TEMPLATES: P2TTemplate[] = [
  {
    id: "pii-protection",
    name: "PII Protection",
    description: "Detect and redact PII (SSNs, emails, phone numbers, credit cards) in AI outputs",
    params: [
      {
        name: "severity",
        type: "string",
        required: false,
        default: "modify",
        description: "Violation severity: block or modify",
      },
      {
        name: "replacement_text",
        type: "string",
        required: false,
        default: "[REDACTED]",
        description: "Replacement text for redacted PII",
      },
      {
        name: "fields_to_check",
        type: "string[]",
        required: false,
        default: ["output.contains_pii", "output.contains_ssn", "output.contains_email"],
        description: "Fields to check for PII",
      },
    ],
  },
  {
    id: "rate-limiting",
    name: "Rate Limiting",
    description: "Rate limit AI actions by user, session, or organization",
    params: [
      { name: "max_requests", type: "number", required: true, description: "Maximum requests per window" },
      {
        name: "window",
        type: "string",
        required: false,
        default: "PT1H",
        description: "Time window (ISO 8601 duration)",
      },
      {
        name: "scope",
        type: "string",
        required: false,
        default: "user",
        description: "Rate limit scope: user or session",
      },
    ],
  },
  {
    id: "content-safety",
    name: "Content Safety",
    description: "Block toxic, harmful, or NSFW content by toxicity score",
    params: [
      {
        name: "toxicity_threshold",
        type: "number",
        required: false,
        default: 0.7,
        description: "Toxicity score threshold (0.0-1.0)",
      },
      {
        name: "categories_to_block",
        type: "string[]",
        required: false,
        default: ["hate_speech", "self_harm", "violence", "sexual_content"],
        description: "Content categories to block",
      },
    ],
  },
  {
    id: "access-control",
    name: "Access Control",
    description: "Require authentication and specific roles for AI actions",
    params: [
      {
        name: "required_roles",
        type: "string[]",
        required: false,
        default: [],
        description: "Roles required to perform actions (empty = any authenticated user)",
      },
      {
        name: "require_auth",
        type: "boolean",
        required: false,
        default: true,
        description: "Whether authentication is required",
      },
    ],
  },
  {
    id: "model-governance",
    name: "Model Governance",
    description: "Restrict which AI models can be used and enforce model hash verification",
    params: [
      { name: "allowed_models", type: "string[]", required: true, description: "List of allowed model IDs" },
      {
        name: "require_hash",
        type: "boolean",
        required: false,
        default: false,
        description: "Whether model hash verification is required",
      },
      {
        name: "provider",
        type: "string",
        required: false,
        default: "any",
        description: "Model provider to restrict to",
      },
    ],
  },
  {
    id: "compliance-baseline",
    name: "Compliance Baseline",
    description: "Generate a baseline compliance contract for common frameworks",
    params: [
      {
        name: "frameworks",
        type: "string[]",
        required: true,
        description: "Compliance frameworks: soc2, gdpr, hipaa, eu-ai-act, nist",
      },
      {
        name: "retention_period",
        type: "string",
        required: false,
        default: "P365D",
        description: "Data retention period (ISO 8601)",
      },
    ],
  },
];

// ─── Template Generators ─────────────────────────────────────────────

function generatePiiProtection(params: Record<string, unknown>, meta: ContractMetadata): string {
  const severity = (params.severity as string) || "modify";
  const replacement = (params.replacement_text as string) || "[REDACTED]";
  const isBlock = severity === "block";

  return formatYAML(
    meta,
    {
      allowed_input_classes: ["public", "internal"],
      allowed_output_classes: ["public"],
      retention_period: "P90D",
      cross_border_transfer: false,
    },
    [
      {
        id: "PII-001",
        description: "Detect and handle PII in outputs",
        action: "*",
        field: "output.contains_pii",
        operator: "equals",
        value: "false",
        on_violation: isBlock ? "block" : "modify",
        message: "Output contains personally identifiable information",
        tags: ["pii", "privacy", "gdpr"],
        ...(isBlock
          ? {}
          : {
              obligations: [{ obligation_id: "OBL-REDACT-PII", type: "redact_pii", params: { replacement } }],
            }),
      },
      {
        id: "PII-002",
        description: "Block SSN exposure",
        action: "*",
        field: "output.contains_ssn",
        operator: "equals",
        value: "false",
        on_violation: "block",
        message: "Output contains Social Security Numbers",
        tags: ["pii", "ssn", "critical"],
      },
    ],
  );
}

function generateRateLimiting(params: Record<string, unknown>, meta: ContractMetadata): string {
  const maxReqs = params.max_requests as number;
  const window = (params.window as string) || "PT1H";
  const scope = (params.scope as string) || "user";

  return formatYAML(
    meta,
    {
      allowed_input_classes: ["public"],
      allowed_output_classes: ["public"],
      retention_period: "P30D",
      cross_border_transfer: false,
    },
    [
      {
        id: "RATE-001",
        description: `Rate limit: ${maxReqs} requests per ${window} per ${scope}`,
        action: "*",
        field: `caller.${scope === "session" ? "session_id" : "user_id"}`,
        operator: "rate_limit",
        value: "",
        on_violation: "block",
        message: "Rate limit exceeded",
        tags: ["rate-limit", "availability"],
        rateLimitMax: maxReqs,
        rateLimitWindow: window,
      },
    ],
  );
}

function generateContentSafety(params: Record<string, unknown>, meta: ContractMetadata): string {
  const threshold = (params.toxicity_threshold as number) ?? 0.7;
  const categories = (params.categories_to_block as string[]) || [
    "hate_speech",
    "self_harm",
    "violence",
    "sexual_content",
  ];

  const rules: RuleSpec[] = [
    {
      id: "SAFETY-001",
      description: `Block content with toxicity score >= ${threshold}`,
      action: "generate",
      field: "output.toxicity_score",
      operator: "less_than",
      value: String(threshold),
      on_violation: "block",
      message: "Content toxicity score exceeds threshold",
      tags: ["safety", "toxicity", "content-moderation"],
    },
  ];

  categories.forEach((cat, i) => {
    rules.push({
      id: `SAFETY-${String(i + 2).padStart(3, "0")}`,
      description: `Block ${cat.replace(/_/g, " ")} content`,
      action: "generate",
      field: `output.categories`,
      operator: "not_contains",
      value: `"${cat}"`,
      on_violation: "block",
      message: `Content classified as ${cat.replace(/_/g, " ")}`,
      tags: ["safety", cat, "content-moderation"],
    });
  });

  return formatYAML(
    meta,
    {
      allowed_input_classes: ["public"],
      allowed_output_classes: ["public"],
      retention_period: "P90D",
      cross_border_transfer: false,
    },
    rules,
  );
}

function generateAccessControl(params: Record<string, unknown>, meta: ContractMetadata): string {
  const roles = (params.required_roles as string[]) || [];
  const requireAuth = params.require_auth !== false;

  const rules: RuleSpec[] = [];

  if (requireAuth) {
    rules.push({
      id: "AUTH-001",
      description: "Require authenticated caller",
      action: "*",
      field: "caller.user_id",
      operator: "exists",
      value: "true",
      on_violation: "block",
      message: "Authentication required",
      tags: ["access-control", "authentication"],
    });
  }

  if (roles.length > 0) {
    rules.push({
      id: "AUTH-002",
      description: `Require one of roles: ${roles.join(", ")}`,
      action: "*",
      field: "caller.roles",
      operator: "contains",
      value: `"${roles[0]}"`,
      on_violation: "block",
      message: `Required role not found. Allowed: ${roles.join(", ")}`,
      tags: ["access-control", "authorization"],
    });
  }

  return formatYAML(
    meta,
    {
      allowed_input_classes: ["public", "internal"],
      allowed_output_classes: ["public"],
      retention_period: "P90D",
      cross_border_transfer: false,
    },
    rules,
  );
}

function generateModelGovernance(params: Record<string, unknown>, meta: ContractMetadata): string {
  const models = params.allowed_models as string[];
  const modelsStr = models.map((m) => `"${m}"`).join(", ");

  return formatYAML(
    meta,
    {
      allowed_input_classes: ["public"],
      allowed_output_classes: ["public"],
      retention_period: "P90D",
      cross_border_transfer: false,
    },
    [
      {
        id: "MODEL-001",
        description: "Restrict to approved models",
        action: "*",
        field: "metadata.model_id",
        operator: "in",
        value: `[${modelsStr}]`,
        on_violation: "block",
        message: `Model not in approved list: ${models.join(", ")}`,
        tags: ["model-governance", "compliance"],
      },
    ],
    models.map((m) => ({
      model_id: m,
      provider: (params.provider as string) || "any",
    })),
  );
}

function generateComplianceBaseline(params: Record<string, unknown>, meta: ContractMetadata): string {
  const frameworks = params.frameworks as string[];
  const retention = (params.retention_period as string) || "P365D";

  const rules: RuleSpec[] = [];

  // Common to all frameworks: require authentication
  rules.push({
    id: "COMP-001",
    description: "Require authenticated caller",
    action: "*",
    field: "caller.user_id",
    operator: "exists",
    value: "true",
    on_violation: "block",
    message: "Unauthenticated request",
    tags: ["compliance", "access-control", ...frameworks],
  });

  // Common: audit logging
  rules.push({
    id: "COMP-002",
    description: "Log all actions for audit trail",
    action: "*",
    field: "caller.session_id",
    operator: "exists",
    value: "true",
    on_violation: "log",
    tags: ["compliance", "audit", ...frameworks],
  });

  if (frameworks.includes("gdpr")) {
    rules.push({
      id: "COMP-GDPR-001",
      description: "Block restricted data in outputs (GDPR Art 32)",
      action: "*",
      field: "output.data_classification",
      operator: "not_in",
      value: '["restricted", "confidential"]',
      on_violation: "block",
      message: "Output contains restricted data class",
      tags: ["compliance", "gdpr", "data-governance"],
    });
  }

  if (frameworks.includes("hipaa")) {
    rules.push({
      id: "COMP-HIPAA-001",
      description: "Block PHI in outputs (HIPAA 164.502)",
      action: "*",
      field: "output.contains_phi",
      operator: "equals",
      value: "false",
      on_violation: "block",
      message: "Output contains Protected Health Information",
      tags: ["compliance", "hipaa", "phi"],
    });
  }

  if (frameworks.includes("eu-ai-act")) {
    rules.push({
      id: "COMP-EUAI-001",
      description: "Require AI disclosure (EU AI Act Art 13)",
      action: "generate",
      field: "metadata.ai_disclosure",
      operator: "equals",
      value: "true",
      on_violation: "modify",
      message: "AI disclosure required",
      tags: ["compliance", "eu-ai-act", "transparency"],
      obligations: [
        {
          obligation_id: "OBL-DISCLOSURE",
          type: "append_notice",
          params: { text: "This content was generated by an AI system." },
        },
      ],
    });
  }

  if (frameworks.includes("soc2")) {
    rules.push({
      id: "COMP-SOC2-001",
      description: "Enterprise rate limit (SOC 2 CC6.6)",
      action: "*",
      field: "caller.user_id",
      operator: "rate_limit",
      value: "",
      on_violation: "block",
      message: "Enterprise rate limit exceeded",
      tags: ["compliance", "soc2", "rate-limit"],
      rateLimitMax: 1000,
      rateLimitWindow: "PT1H",
    });
  }

  return formatYAML(
    meta,
    {
      allowed_input_classes: ["public", "internal"],
      allowed_output_classes: ["public"],
      retention_period: retention,
      cross_border_transfer: false,
    },
    rules,
  );
}

// ─── YAML Formatter ──────────────────────────────────────────────────

interface RuleSpec {
  id: string;
  description: string;
  action: string;
  field: string;
  operator: string;
  value: string;
  on_violation: string;
  message?: string;
  tags: string[];
  obligations?: Array<{ obligation_id: string; type: string; params?: Record<string, unknown> }>;
  rateLimitMax?: number;
  rateLimitWindow?: string;
}

interface DataGovSpec {
  allowed_input_classes: string[];
  allowed_output_classes: string[];
  retention_period: string;
  cross_border_transfer: boolean;
}

interface ModelSpec {
  model_id: string;
  provider: string;
}

function formatYAML(meta: ContractMetadata, dg: DataGovSpec, rules: RuleSpec[], modelBindings?: ModelSpec[]): string {
  let yaml = `schema_version: "1.0"
metadata:
  name: ${meta.name}
  version: "${meta.version}"
  author: ${meta.author}
  description: >
    ${meta.description}
  effective_date: "${meta.effective_date}"`;

  if (meta.review_date) {
    yaml += `\n  review_date: "${meta.review_date}"`;
  }
  if (meta.stakeholders?.length) {
    yaml += `\n  stakeholders: [${meta.stakeholders.join(", ")}]`;
  }

  yaml += `

data_governance:
  allowed_input_classes: [${dg.allowed_input_classes.join(", ")}]
  allowed_output_classes: [${dg.allowed_output_classes.join(", ")}]
  retention_period: ${dg.retention_period}
  cross_border_transfer: ${dg.cross_border_transfer}`;

  if (modelBindings?.length) {
    yaml += `\n\nmodel_bindings:`;
    for (const mb of modelBindings) {
      yaml += `\n  - model_id: "${mb.model_id}"\n    provider: "${mb.provider}"`;
    }
  }

  yaml += `\n\nrules:`;
  for (const rule of rules) {
    const needsQuote = rule.description.includes(":") || rule.description.includes("#");
    const descStr = needsQuote ? `"${rule.description.replace(/"/g, '\\"')}"` : rule.description;
    yaml += `\n  - id: ${rule.id}
    description: ${descStr}
    action: "${rule.action}"
    conditions:
      - field: ${rule.field}
        operator: ${rule.operator}`;

    if (rule.rateLimitMax !== undefined) {
      yaml += `\n        value:\n          max: ${rule.rateLimitMax}\n          window: ${rule.rateLimitWindow}`;
    } else {
      yaml += `\n        value: ${rule.value}`;
    }

    yaml += `\n    on_violation: ${rule.on_violation}`;

    if (rule.message) {
      yaml += `\n    message: "${rule.message.replace(/"/g, '\\"')}"`;
    }

    if (rule.obligations?.length) {
      yaml += `\n    obligations:`;
      for (const obl of rule.obligations) {
        yaml += `\n      - obligation_id: ${obl.obligation_id}
        type: ${obl.type}`;
        if (obl.params) {
          yaml += `\n        params:`;
          for (const [k, v] of Object.entries(obl.params)) {
            yaml += `\n          ${k}: "${v}"`;
          }
        }
      }
    }

    yaml += `\n    tags: [${rule.tags.join(", ")}]`;
  }

  return yaml + "\n";
}

// ─── P2T Generator Class ─────────────────────────────────────────────

const GENERATORS: Record<string, (params: Record<string, unknown>, meta: ContractMetadata) => string> = {
  "pii-protection": generatePiiProtection,
  "rate-limiting": generateRateLimiting,
  "content-safety": generateContentSafety,
  "access-control": generateAccessControl,
  "model-governance": generateModelGovernance,
  "compliance-baseline": generateComplianceBaseline,
};

/**
 * Policy-to-Trust (P2T) contract generator.
 *
 * Generates YAML trust contract skeletons from templates and parameters.
 * Built-in templates cover common governance patterns: PII protection,
 * rate limiting, content safety, access control, model governance, and
 * compliance baselines.
 */
export class P2TGenerator {
  private templates: P2TTemplate[];

  constructor() {
    this.templates = [...TEMPLATES];
  }

  /**
   * Generate a YAML trust contract from a template.
   *
   * @param input - Template ID, parameters, and optional metadata overrides
   * @returns YAML string of the generated contract
   * @throws Error if template not found or required params missing
   */
  generate(input: P2TInput): string {
    const template = this.templates.find((t) => t.id === input.template);
    if (!template) {
      throw new Error(
        `Unknown template: "${input.template}". Available: ${this.templates.map((t) => t.id).join(", ")}`,
      );
    }

    // Validate required params
    for (const param of template.params) {
      if (param.required && !(param.name in input.params)) {
        throw new Error(`Missing required parameter "${param.name}" for template "${template.id}"`);
      }
    }

    // Apply defaults
    const params = { ...input.params };
    for (const param of template.params) {
      if (!(param.name in params) && param.default !== undefined) {
        params[param.name] = param.default;
      }
    }

    // Build metadata
    const now = new Date().toISOString().split("T")[0];
    const meta: ContractMetadata = {
      name: input.metadata?.name || template.name,
      version: input.metadata?.version || "1.0.0",
      author: input.metadata?.author || "P2T Generator",
      description: input.metadata?.description || template.description,
      effective_date: input.metadata?.effective_date || now,
      review_date: input.metadata?.review_date,
      stakeholders: input.metadata?.stakeholders,
    };

    const generator = GENERATORS[template.id];
    if (!generator) {
      throw new Error(`No generator found for template "${template.id}"`);
    }

    return generator(params, meta);
  }

  /** List all available templates. */
  listTemplates(): P2TTemplate[] {
    return [...this.templates];
  }

  /** Register a custom template. */
  registerTemplate(
    template: P2TTemplate,
    generator: (params: Record<string, unknown>, meta: ContractMetadata) => string,
  ): void {
    this.templates.push(template);
    GENERATORS[template.id] = generator;
  }
}
