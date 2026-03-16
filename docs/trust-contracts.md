# Trust Contract Authoring Guide

A trust contract is a YAML document that defines what an AI system is allowed to do, under what conditions, and what happens when violations occur.

## Contract Structure

Every contract has four required sections:

```yaml
schema_version: "1.0"      # Always "1.0" for now
metadata: { ... }           # Who, what, when
data_governance: { ... }    # Data handling rules
rules: [ ... ]              # Enforceable policy rules
```

## Metadata

```yaml
metadata:
  name: Healthcare AI Governance       # Unique contract name
  version: "1.0.0"                     # Semantic version
  author: Compliance Team              # Who wrote this
  description: >                       # What it governs
    Governs AI-assisted clinical decision support.
  effective_date: "2026-01-01"         # When it takes effect
  review_date: "2026-06-01"           # When to review (optional)
  stakeholders:                        # Who cares about this (optional)
    - Chief Medical Officer
    - Data Protection Officer
```

## Data Governance

Declares what data classes are permitted as input/output:

```yaml
data_governance:
  allowed_input_classes:
    - phi          # Protected Health Information
    - internal     # Internal company data
  allowed_output_classes:
    - internal
    - public       # Safe for public consumption
  retention_period: P90D      # ISO 8601 duration (90 days)
  cross_border_transfer: false
```

Available data classes: `pii`, `phi`, `financial`, `credentials`, `public`, `internal`, `confidential`

## Rules

Each rule defines a governance constraint:

```yaml
rules:
  - id: HC-001                              # Unique identifier
    description: PHI must not appear in outputs  # Human-readable
    action: "*"                              # Which actions this applies to
    conditions:                              # What must be true
      - field: output.contains_phi
        operator: equals
        value: false
    on_violation: block                      # What happens if conditions fail
    tags: [hipaa, data-protection]          # Categorization tags
```

### Actions

The `action` field specifies which AI operations this rule governs:

- A single verb: `action: generate`
- Multiple verbs: `action: [generate, summarize, translate]`
- All actions: `action: "*"` (wildcard)

Built-in verbs: `generate`, `classify`, `summarize`, `translate`, `extract`, `transform`, `decide`, `recommend`

Custom verbs are allowed — use any string.

### Severity Levels

| Severity | Effect | Use When |
|---|---|---|
| `block` | Decision becomes `deny`. Action is prevented. | Safety-critical violations |
| `modify` | Decision becomes `modify`. Obligations are attached. | Fixable issues (redact PII, add disclaimer) |
| `warn` | Warning recorded. Action still proceeds. | Important but non-blocking concerns |
| `log` | Logged only. No effect on decision. | Audit trail / analytics |

### Conditions

#### Leaf Conditions

A leaf condition compares a field value against an expected value:

```yaml
conditions:
  - field: output.confidence    # Dot-notation path
    operator: greater_than      # Comparison operator
    value: 0.85                 # Expected value
```

**Field resolution paths:**
- `input.prompt` → `context.input.prompt`
- `output.confidence` → `context.output.confidence`
- `caller.user_id` → `context.caller.user_id`
- `caller.roles` → `context.caller.roles`
- `metadata.approved` → `context.metadata.approved`
- `action` → `context.action`

#### Operators

| Operator | Types | Description |
|---|---|---|
| `equals` | any | Exact equality |
| `not_equals` | any | Not equal |
| `contains` | string, array | String includes substring, or array includes element |
| `not_contains` | string, array | Opposite of contains |
| `greater_than` | number | Strictly greater |
| `less_than` | number | Strictly less |
| `in` | any | Value is in the provided array |
| `not_in` | any | Value is not in the provided array |
| `matches` | string | Regex match (value is the pattern) |
| `exists` | any | Field is present and not undefined |
| `not_exists` | any | Field is absent or undefined |
| `rate_limit` | string (key field) | Sliding window rate counter |

#### Rate Limiting

```yaml
conditions:
  - field: caller.user_id
    operator: rate_limit
    value:
      max: 100        # Maximum count in window
      window: "PT1H"  # ISO 8601 duration (1 hour)
```

Supported duration formats: `PT30S` (30 seconds), `PT5M` (5 minutes), `PT1H` (1 hour), `PT1H30M` (90 minutes), `P1D` (1 day), `P7D` (7 days), `P7DT12H` (7.5 days)

Requires a `StateStore` to be configured:

```typescript
import { GodClause, MemoryStateStore } from "god-clause";
const gov = new GodClause({ stateStore: new MemoryStateStore() });
```

#### Composite Conditions

Combine conditions with boolean logic:

**AND (all must pass):**
```yaml
conditions:
  - all:
      - field: caller.roles
        operator: contains
        value: analyst
      - field: output.confidence
        operator: greater_than
        value: 0.9
```

**OR (at least one must pass):**
```yaml
conditions:
  - any:
      - field: caller.roles
        operator: contains
        value: senior_analyst
      - field: metadata.manager_approved
        operator: equals
        value: true
```

**NOT (must not pass):**
```yaml
conditions:
  - not:
      field: output.flagged_bias
      operator: equals
      value: true
```

**Nested (arbitrary depth):**
```yaml
conditions:
  - all:
      - any:
          - field: caller.roles
            operator: contains
            value: admin
          - all:
              - field: caller.roles
                operator: contains
                value: analyst
              - field: metadata.approved
                operator: equals
                value: true
      - not:
          field: output.contains_pii
          operator: equals
          value: true
```

### Obligations

Obligations are remediation actions attached to `modify`-severity rules:

```yaml
rules:
  - id: PII-REDACT
    description: Redact PII from outputs instead of blocking
    action: generate
    conditions:
      - field: output.contains_pii
        operator: equals
        value: false
    on_violation: modify
    obligations:
      - obligation_id: OBL-001
        type: redact_pii
        params:
          fields: [name, email, phone]
      - obligation_id: OBL-002
        type: add_disclaimer
        params:
          text: "This output has been modified for privacy compliance."
```

When the condition fails, the decision outcome is `modify` (not `deny`), and the obligations array tells the application what to do before proceeding.

### Tags

Tags categorize rules for filtering and analytics:

```yaml
rules:
  - id: SAFETY-001
    tags: [safety, content-moderation, priority-high]
```

At evaluation time, filter by tags:

```typescript
// Only evaluate safety rules
await gov.evaluate(ctx, { includeTags: ["safety"] });

// Evaluate everything except experimental rules
await gov.evaluate(ctx, { excludeTags: ["experimental"] });
```

## Complete Example

```yaml
schema_version: "1.0"

metadata:
  name: Financial AI Governance
  version: "2.0.0"
  author: Risk & Compliance
  description: >
    Governs AI-driven trading recommendations and risk assessments.
    Enforces regulatory requirements and internal risk policies.
  effective_date: "2026-01-01"
  review_date: "2026-04-01"
  stakeholders:
    - Chief Risk Officer
    - Head of Compliance
    - Trading Desk Lead

data_governance:
  allowed_input_classes: [financial, internal]
  allowed_output_classes: [internal]
  retention_period: P7Y        # 7-year regulatory retention
  cross_border_transfer: false

rules:
  - id: FIN-001
    description: Trading recommendations require senior analyst or manager approval
    action: recommend
    conditions:
      - any:
          - field: caller.roles
            operator: contains
            value: senior_analyst
          - all:
              - field: caller.roles
                operator: contains
                value: analyst
              - field: metadata.manager_approved
                operator: equals
                value: true
    on_violation: block
    tags: [access-control, regulatory]

  - id: FIN-002
    description: Risk assessments must include confidence score above 0.90
    action: decide
    conditions:
      - field: output.confidence
        operator: greater_than
        value: 0.90
    on_violation: warn
    tags: [quality, risk]

  - id: FIN-003
    description: Redact client identifiers from analytical outputs
    action: [summarize, extract]
    conditions:
      - field: output.contains_client_ids
        operator: equals
        value: false
    on_violation: modify
    tags: [privacy, regulatory]
    obligations:
      - obligation_id: OBL-REDACT-CLIENTS
        type: redact_identifiers
        params:
          categories: [client_id, account_number, ssn]

  - id: FIN-004
    description: Rate limit API usage to 500 requests per hour
    action: "*"
    conditions:
      - field: caller.user_id
        operator: rate_limit
        value: { max: 500, window: "PT1H" }
    on_violation: block
    tags: [rate-limiting, operational]

  - id: FIN-005
    description: Log all model outputs for regulatory audit trail
    action: "*"
    conditions:
      - field: output
        operator: exists
        value: true
    on_violation: log
    tags: [audit, regulatory]
```
