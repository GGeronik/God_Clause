/**
 * JSON Schema for validating trust contract documents.
 *
 * Uses a plain object rather than Ajv's JSONSchemaType generic
 * because the union types in PolicyRule (action: string | string[])
 * and the `unknown` value field are incompatible with Ajv's strict
 * type-level schema inference.
 */
export const trustContractSchema = {
  type: "object",
  required: ["schema_version", "metadata", "data_governance", "rules"],
  $defs: {
    conditionExpr: {
      oneOf: [
        {
          type: "object",
          required: ["field", "operator", "value"],
          additionalProperties: false,
          properties: {
            field: { type: "string" },
            operator: {
              type: "string",
              enum: [
                "equals",
                "not_equals",
                "contains",
                "not_contains",
                "greater_than",
                "less_than",
                "in",
                "not_in",
                "matches",
                "exists",
                "not_exists",
                "rate_limit",
              ],
            },
            value: {},
          },
        },
        {
          type: "object",
          required: ["all"],
          additionalProperties: false,
          properties: {
            all: {
              type: "array",
              items: { $ref: "#/$defs/conditionExpr" },
            },
          },
        },
        {
          type: "object",
          required: ["any"],
          additionalProperties: false,
          properties: {
            any: {
              type: "array",
              items: { $ref: "#/$defs/conditionExpr" },
            },
          },
        },
        {
          type: "object",
          required: ["not"],
          additionalProperties: false,
          properties: {
            not: { $ref: "#/$defs/conditionExpr" },
          },
        },
      ],
    },
  },
  properties: {
    schema_version: { type: "string" },
    plain_language_summary: { type: "string", nullable: true },
    metadata: {
      type: "object",
      required: ["name", "version", "author", "description", "effective_date"],
      additionalProperties: false,
      properties: {
        name: { type: "string" },
        version: { type: "string" },
        author: { type: "string" },
        description: { type: "string" },
        effective_date: { type: "string" },
        review_date: { type: "string", nullable: true },
        stakeholders: {
          type: "array",
          items: { type: "string" },
          nullable: true,
        },
      },
    },
    data_governance: {
      type: "object",
      required: ["allowed_input_classes", "allowed_output_classes", "retention_period", "cross_border_transfer"],
      additionalProperties: false,
      properties: {
        allowed_input_classes: {
          type: "array",
          items: {
            type: "string",
            enum: ["pii", "phi", "financial", "credentials", "public", "internal", "confidential"],
          },
        },
        allowed_output_classes: {
          type: "array",
          items: {
            type: "string",
            enum: ["pii", "phi", "financial", "credentials", "public", "internal", "confidential"],
          },
        },
        retention_period: { type: "string" },
        cross_border_transfer: { type: "boolean" },
      },
    },
    extends: { type: "string", nullable: true },
    model_bindings: {
      type: "array",
      items: {
        type: "object",
        required: ["model_id", "provider"],
        properties: {
          model_id: { type: "string" },
          provider: { type: "string" },
          sha256: { type: "string", nullable: true },
          allowed_actions: { type: "array", items: { type: "string" }, nullable: true },
          max_tokens: { type: "number", nullable: true },
          temperature_max: { type: "number", nullable: true },
        },
      },
      nullable: true,
    },
    mcp_permissions: {
      type: "array",
      items: {
        type: "object",
        required: ["tool_pattern", "allowed"],
        properties: {
          tool_pattern: { type: "string" },
          allowed: { type: "boolean" },
          conditions: { type: "array", items: { $ref: "#/$defs/conditionExpr" }, nullable: true },
          require_human_approval: { type: "boolean", nullable: true },
          max_calls_per_session: { type: "number", nullable: true },
          audit_level: { type: "string", enum: ["full", "summary", "none"], nullable: true },
        },
      },
      nullable: true,
    },
    degradation_tiers: {
      type: "array",
      items: {
        type: "object",
        required: ["tier", "name", "trigger", "capabilities", "blocked_actions"],
        properties: {
          tier: { type: "number" },
          name: { type: "string" },
          trigger: { type: "string" },
          capabilities: { type: "array", items: { type: "string" } },
          blocked_actions: { type: "array", items: { type: "string" } },
          notify: { type: "array", items: { type: "string" }, nullable: true },
        },
      },
      nullable: true,
    },
    override_rules: {
      type: "array",
      items: {
        type: "object",
        required: ["id", "description", "action", "conditions", "on_violation"],
        additionalProperties: false,
        properties: {
          id: { type: "string" },
          description: { type: "string" },
          action: {
            oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }],
          },
          conditions: {
            type: "array",
            items: { $ref: "#/$defs/conditionExpr" },
          },
          on_violation: {
            type: "string",
            enum: ["block", "warn", "log", "modify"],
          },
          tags: {
            type: "array",
            items: { type: "string" },
            nullable: true,
          },
          obligations: {
            type: "array",
            items: {
              type: "object",
              required: ["obligation_id", "type"],
              additionalProperties: false,
              properties: {
                obligation_id: { type: "string" },
                type: { type: "string" },
                params: { type: "object" },
              },
            },
            nullable: true,
          },
          message: { type: "string", nullable: true },
          hazard_class: { type: "string", nullable: true },
          scope: {
            type: "object",
            properties: {
              models: { type: "array", items: { type: "string" }, nullable: true },
              actions: { type: "array", items: { type: "string" }, nullable: true },
              data_classes: { type: "array", items: { type: "string" }, nullable: true },
            },
            nullable: true,
          },
          exceptions: { type: "array", items: { $ref: "#/$defs/conditionExpr" }, nullable: true },
          required_evidence: { type: "array", items: { type: "string" }, nullable: true },
        },
      },
      nullable: true,
    },
    rules: {
      type: "array",
      items: {
        type: "object",
        required: ["id", "description", "action", "conditions", "on_violation"],
        additionalProperties: false,
        properties: {
          id: { type: "string" },
          description: { type: "string" },
          action: {
            oneOf: [{ type: "string" }, { type: "array", items: { type: "string" } }],
          },
          conditions: {
            type: "array",
            items: { $ref: "#/$defs/conditionExpr" },
          },
          on_violation: {
            type: "string",
            enum: ["block", "warn", "log", "modify"],
          },
          tags: {
            type: "array",
            items: { type: "string" },
            nullable: true,
          },
          obligations: {
            type: "array",
            items: {
              type: "object",
              required: ["obligation_id", "type"],
              additionalProperties: false,
              properties: {
                obligation_id: { type: "string" },
                type: { type: "string" },
                params: { type: "object" },
              },
            },
            nullable: true,
          },
          message: { type: "string", nullable: true },
          hazard_class: { type: "string", nullable: true },
          scope: {
            type: "object",
            properties: {
              models: { type: "array", items: { type: "string" }, nullable: true },
              actions: { type: "array", items: { type: "string" }, nullable: true },
              data_classes: { type: "array", items: { type: "string" }, nullable: true },
            },
            nullable: true,
          },
          exceptions: { type: "array", items: { $ref: "#/$defs/conditionExpr" }, nullable: true },
          required_evidence: { type: "array", items: { type: "string" }, nullable: true },
        },
      },
    },
  },
};
