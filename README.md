# God Clause

**Open-source AI policy engine** — enforce rules, redact PII, prove compliance. Every decision cryptographically sealed.

> OPA does Allow/Deny. God Clause does Allow/Deny/**Modify** — redact PII, add disclaimers, truncate outputs, all in the critical path. Every decision is SHA-256 hash-chained. Every policy is cryptographically signed.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-green.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)]()
[![Tests](https://img.shields.io/badge/tests-504%20passing-brightgreen.svg)]()

---

## See It Work: PII Redaction in 10 Lines

```typescript
import { GodClause } from "god-clause";

const gov = new GodClause();
gov.loadContractYAML(`
  schema_version: "1.0"
  metadata:
    name: PII Safety
    version: "1.0.0"
    author: Platform Team
    description: Redact PII from AI outputs
    effective_date: "2025-01-01"
  data_governance:
    allowed_input_classes: [public, internal]
    allowed_output_classes: [public]
    retention_period: P90D
    cross_border_transfer: false
  rules:
    - id: PII-001
      description: Redact PII instead of blocking
      action: generate
      conditions:
        - field: output.contains_pii
          operator: equals
          value: false
      on_violation: modify
      obligations:
        - obligation_id: OBL-REDACT
          type: redact_pii
          params: { replacement: "[REDACTED]" }
      tags: [privacy, pii]
`);

// LLM returns output containing a Social Security Number
const decision = await gov.evaluate({
  action: "generate",
  input: { prompt: "Look up John's records" },
  output: { text: "John's SSN is 123-45-6789", contains_pii: true },
  caller: { user_id: "u1", session_id: "s1", roles: ["analyst"] },
});

console.log(decision.outcome);        // "modify"  (not blocked — modified)
console.log(decision.obligations[0]); // { type: "redact_pii", params: { replacement: "[REDACTED]" } }

// Your app applies the obligation:
// "John's SSN is 123-45-6789"  →  "John's SSN is [REDACTED]"

// Meanwhile, the hash-chained audit log recorded everything:
const { valid } = gov.verifyAuditChain();
console.log(valid); // true — tamper-evident proof this decision happened
```

**Before**: `"John's SSN is 123-45-6789"`
**After**: `"John's SSN is [REDACTED]"`
**Audit**: SHA-256 hash-chained, HMAC-signed, Merkle-sealed.

No other policy engine does this. OPA blocks or allows. God Clause **transforms**.

---

## Why God Clause?

### For Developers: Drop-in AI safety in 5 lines

| What you get | How |
|---|---|
| PII redaction | `on_violation: modify` + `redact_pii` obligation |
| Prompt injection blocking | Condition on `input.injection_score` |
| Toxicity filtering | Condition on `output.toxicity_score` |
| Rate limiting | Built-in sliding window per user/org |
| Output truncation | Modify obligation with `max_tokens` |

No sidecars. No Docker. No external services. `npm install god-clause` and write a YAML file.

### For CISOs: Automated compliance evidence

| Regulation | What God Clause provides |
|---|---|
| EU AI Act Article 12 | Automatic logging of every AI decision with tamper-evident hash chain |
| SOC 2 CC6.1 | Cryptographic integrity controls via HMAC-SHA256 + Merkle seals |
| GDPR Article 32 | Technical measures (PII redaction, data governance declarations) |
| HIPAA | PHI protection rules, role-based access control, audit trails |
| NIST AI RMF | Policy-based risk management with tag-filtered rule evaluation |
| ISO 42001 | Documented AI governance with versioned, signed policy contracts |

Generate compliance reports programmatically: `generateComplianceReport(gov, "eu-ai-act")`.

---

## Why Trust Contracts Are Not Config Files

A Trust Contract is a YAML file — but it's not "just configuration."

The SHA-256 hash of your YAML policy is embedded into every audit entry's hash chain. The policy fingerprint (`governance_context.policy_sha256`) is recorded with every decision. Tampering with the contract retroactively invalidates the entire audit trail.

Add DSSE cryptographic signatures to prove who authored each policy. Add RFC 3161 timestamps to prove when it was signed. Together: **legally defensible, evidence-grade governance** — not a config file.

```yaml
schema_version: "1.0"
metadata:
  name: Content Safety Policy         # Human-readable
  version: "2.1.0"                    # Versioned
  author: AI Safety Team              # Attributable
  description: Safety guardrails for production LLM
  effective_date: "2025-01-01"
  review_date: "2025-07-01"
  stakeholders: [VP Engineering, Legal, Ethics Board]
data_governance:
  allowed_input_classes: [public, internal]
  allowed_output_classes: [public]     # No PII/PHI in outputs
  retention_period: P90D
  cross_border_transfer: false
rules:
  - id: SAFETY-001
    description: Block toxic content
    action: generate
    conditions:
      - field: output.toxicity_score
        operator: less_than
        value: 0.3
    on_violation: block
    tags: [safety, content]
  - id: PII-001
    description: Redact PII instead of blocking users
    action: generate
    conditions:
      - field: output.contains_pii
        operator: equals
        value: false
    on_violation: modify
    obligations:
      - obligation_id: OBL-REDACT
        type: redact_pii
        params: { fields: [ssn, email, phone] }
    tags: [privacy, compliance]
```

A lawyer can read it. An engineer can enforce it. An auditor can verify it. Same file.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Trust Contracts                    │
│  Human-readable YAML with machine-enforceable rules │
│  Schema-validated · Versioned · DSSE-signed          │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│              Runtime Policy Engine                   │
│  Recursive AND/OR/NOT · Rate limiting · Tag filters  │
│  Three-valued: permit / deny / modify (obligations)  │
└──────────────────────┬──────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────┐
│             Evidence-Grade Audit Trail               │
│  SHA-256 hash chain · HMAC-SHA256 signing            │
│  Merkle seals · RFC 3161 timestamps · OTel export    │
└─────────────────────────────────────────────────────┘
```

### Deployment Modes

| Mode | Use case |
|---|---|
| **Embedded library** | TypeScript/Node.js apps — `import { GodClause }` |
| **REST API server** | Python/Java/Go — call `POST /v1/evaluate` |
| **Kubernetes sidecar** | Platform teams — Helm chart + ConfigMap contracts |
| **Serverless** | Lambda/Cloud Functions — import the library directly |

---

## Evidence-Grade Audit (Why Hash Chains Beat Database Logs)

Database audit logs can be silently edited by DBAs. Regulators know this. God Clause's audit trail is different:

| Layer | What it proves |
|---|---|
| **SHA-256 hash chain** | Each entry links to the previous. Delete or modify any entry → chain breaks → tampering detected |
| **HMAC-SHA256 signing** | Even if someone recomputes hashes, they need the secret key |
| **Merkle seal checkpoints** | O(log n) verification over audit segments |
| **RFC 3161 timestamps** | External trusted clock proves a seal existed at a specific time |
| **DSSE contract signatures** | Cryptographic proof of who authored each policy |

This is evidence that holds up in regulatory proceedings. Standard database logs don't pass non-repudiation tests.

---

## Drop-In Threat Contracts

Pre-built contracts for common AI threats. Copy into your project and load:

| Contract | Threats covered |
|---|---|
| [`pii-redaction.contract.yaml`](./examples/threats/pii-redaction.contract.yaml) | SSNs, emails, phone numbers, credit cards |
| [`prompt-injection.contract.yaml`](./examples/threats/prompt-injection.contract.yaml) | Ignore-previous, system prompt extraction, jailbreaks |
| [`anti-hallucination.contract.yaml`](./examples/threats/anti-hallucination.contract.yaml) | Low-confidence outputs, missing citations, factual grounding |
| [`toxic-content.contract.yaml`](./examples/threats/toxic-content.contract.yaml) | Toxicity, NSFW, hate speech, self-harm |
| [`cost-control.contract.yaml`](./examples/threats/cost-control.contract.yaml) | Rate limits, token caps, model restrictions |
| [`data-leakage.contract.yaml`](./examples/threats/data-leakage.contract.yaml) | Internal data in outputs, cross-border violations |
| [`bias-detection.contract.yaml`](./examples/threats/bias-detection.contract.yaml) | Demographic bias in scoring, protected class filtering |
| [`copyright-protection.contract.yaml`](./examples/threats/copyright-protection.contract.yaml) | Verbatim reproduction, attribution requirements |

See also: [domain-specific contracts](./examples/) for healthcare, financial services, HR, and e-commerce.

---

## Features

### Three-Valued Decisions (The Differentiator)
- **Permit** — action proceeds as-is
- **Deny** — action blocked, caller gets structured error
- **Modify** — action proceeds with **obligations**: redact PII, add disclaimers, require human review, truncate output

No other open-source policy engine provides semantic modification in the decision path.

### 12 Condition Operators

| Operator | Example |
|---|---|
| `equals` / `not_equals` | `output.status equals "approved"` |
| `contains` / `not_contains` | `caller.roles contains "admin"` |
| `greater_than` / `less_than` | `output.confidence greater_than 0.85` |
| `in` / `not_in` | `action in [generate, classify]` |
| `matches` | `input.prompt matches "^[A-Za-z ]+$"` (regex) |
| `exists` / `not_exists` | `output.disclaimer exists` |
| `rate_limit` | `caller.user_id rate_limit { max: 100, window: "PT1H" }` |

### Composite Logic
```yaml
conditions:
  - all:                              # AND
      - field: caller.roles
        operator: contains
        value: analyst
      - any:                          # OR
          - field: output.confidence
            operator: greater_than
            value: 0.9
          - field: metadata.approved
            operator: equals
            value: true
      - not:                          # NOT
          field: output.flagged
          operator: equals
          value: true
```

### Everything Else
- **Rate limiting** — sliding window counters with pluggable state store (memory, Redis)
- **Tag filtering** — evaluate rule subsets by tag at runtime
- **Contract versioning** — multiple versions with activate/deactivate
- **Multi-tenancy** — isolated contracts, engine, and audit per tenant
- **DSSE signing** — cryptographic contract authorship via Dead Simple Signing Envelopes
- **RFC 3161 timestamps** — external clock anchoring for Merkle seals
- **OpenTelemetry export** — OTLP/HTTP log mapping for Datadog/Grafana/New Relic
- **Prometheus metrics** — `godclause_decisions_total`, `godclause_blocks_total`, evaluation duration histograms
- **REST API server** — standalone PDP with 15+ endpoints, SSE streaming, batch evaluation
- **CLI tool** — `validate`, `lint`, `summarize`, `diff`, `evaluate`, `serve`, `audit verify/export`, `init`
- **Web dashboard** — React + Vite + Tailwind with live SSE, contract browser, audit explorer
- **6 compliance frameworks** — EU AI Act, NIST AI RMF, ISO 42001, SOC 2, GDPR, HIPAA

---

## Integrations

### HTTP Middleware (Express/Fastify)
```typescript
app.use(godClauseMiddleware(gov, {
  contextExtractor: (req) => ({
    action: "generate",
    input: req.body,
    caller: { user_id: req.user.id, session_id: req.sessionId, roles: req.user.roles },
  }),
}));
// Auto-returns 403 on block, sets warning headers on warn
```

### LangChain
```typescript
const handler = createLangChainCallbackHandler(gov, { caller });
const chain = new LLMChain({ llm, prompt, callbacks: [handler] });
```

### Vercel AI SDK
```typescript
const wrapper = createVercelAIWrapper(gov, { caller });
const result = await wrapper.wrapGenerate({ doGenerate: () => model.doGenerate(params) });
```

### REST API (Any Language)
```bash
# Start server
god-clause serve --port 3000 --contracts ./contracts

# Evaluate from any language
curl -X POST http://localhost:3000/v1/evaluate \
  -H "Content-Type: application/json" \
  -d '{"action":"generate","input":{"prompt":"..."},"output":{"toxicity_score":0.9},"caller":{"user_id":"u1","session_id":"s1","roles":["user"]}}'
```

---

## Comparison

| Feature | God Clause | OPA/Rego | Permit.io | Guardrails AI |
|---|---|---|---|---|
| Three-valued decisions (modify) | Yes | No | No | No |
| Obligations (redact, disclaim, truncate) | Built-in | Custom code | No | No |
| Human-readable policies | YAML | Rego (code) | UI-only | Python decorators |
| Cryptographic audit proof | SHA-256 chain + HMAC + Merkle + DSSE | No | No | No |
| RFC 3161 trusted timestamps | Yes | No | No | No |
| Compliance report generation | 6 frameworks | No | No | No |
| Rate limiting | Built-in | External | Built-in | No |
| Multi-tenancy | Built-in isolation | Namespaces | Built-in | No |
| Embeddable (no server needed) | Yes | Server or WASM | Server | Yes |
| Runtime dependencies | 4 | Go binary | SaaS | Many |
| Open-source license | Apache 2.0 | Apache 2.0 | Partial | Apache 2.0 |

---

## The Adoption Path

**Who it's for**: Platform engineering teams at companies building internal GenAI applications who need drop-in PII redaction and automated audit trails to pass SOC 2 or EU AI Act compliance.

**Day 1**: `npm install god-clause`. Load `pii-redaction.contract.yaml`. Wrap your LLM calls. PII gets redacted, every decision is hash-chained.

**Week 1**: Add `prompt-injection.contract.yaml` and `toxic-content.contract.yaml`. Set up the REST API server so your Python services can call it too.

**Month 1**: Deploy as a Kubernetes sidecar. Connect Prometheus metrics to Grafana. Generate your first SOC 2 compliance report. Hand it to your auditor.

**Quarter 1**: Multi-tenancy for different product teams. DSSE-signed contracts in your policy repo. RFC 3161 timestamps on Merkle seals. Your CISO sleeps better.

---

## API Reference

### `GodClause`

| Method | Returns | Description |
|---|---|---|
| `loadContractYAML(yaml)` | `TrustContract` | Parse and activate a YAML/JSON contract |
| `loadContract(contract)` | `void` | Load a pre-parsed contract object |
| `evaluate(ctx, opts?)` | `Promise<PolicyDecision>` | Evaluate context (non-throwing) |
| `enforce(ctx, opts?)` | `Promise<PolicyDecision>` | Evaluate + throw on block |
| `queryAudit(query)` | `AuditEntry[]` | Search audit entries |
| `verifyAuditChain(key?)` | `{ valid, brokenAt? }` | Verify hash chain integrity |
| `sealAuditChain()` | `ChainSeal` | Create Merkle seal checkpoint |
| `createTenant(id, opts?)` | `TenantScope` | Create isolated tenant scope |

### `PolicyDecision`

| Field | Type | Description |
|---|---|---|
| `outcome` | `"permit" \| "deny" \| "modify"` | Three-valued result |
| `allowed` | `boolean` | `outcome !== "deny"` |
| `obligations` | `Obligation[]` | What to do for modify decisions |
| `blocks` | `RuleEvaluation[]` | Which rules blocked |
| `warnings` | `RuleEvaluation[]` | Which rules warned |
| `governance_context` | `GovernanceContext` | Policy SHA-256 fingerprint |

See [full API docs](./docs/) for server endpoints, CLI commands, and configuration reference.

---

## Examples

- **[Quick Start](./examples/quickstart.ts)** — 30-line PII redaction with audit verification
- **[OpenAI Wrapper](./examples/openai-wrapper.ts)** — Governance around OpenAI calls
- **[Claude Wrapper](./examples/anthropic-wrapper.ts)** — Governance around Anthropic Claude calls
- **[Gemini Wrapper](./examples/gemini-wrapper.ts)** — Governance around Google Gemini calls
- **[MCP Agent Demo](./examples/mcp-agent-demo.ts)** — MCP tool authorization with fail-closed routing
- **[Threat Contracts](./examples/threats/)** — 9 drop-in contracts for common AI threats
- **[Healthcare AI](./examples/healthcare-ai.contract.yaml)** — PHI protection, human-in-the-loop
- **[Financial Services](./examples/financial-services.contract.yaml)** — Regulatory compliance
- **[LLM Safety](./examples/llm-safety.contract.yaml)** — Prompt injection, toxicity, hallucination

---

## AI Onboarding

This repo ships with context files so any AI coding assistant can understand the project immediately:

| File | Assistant | What it does |
|------|-----------|--------------|
| [`CLAUDE.md`](./CLAUDE.md) | Claude Code | Auto-read on session start — full architecture, commands, patterns, and rules |
| [`.cursorrules`](./.cursorrules) | Cursor IDE | Quick reference with architecture map and 9 development rules |
| [`.github/copilot-instructions.md`](./.github/copilot-instructions.md) | GitHub Copilot | Key files, code style, and domain concepts |

**Try it**: Open the project in Claude Code and ask *"What is this project?"* — it already knows.

---

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) for development setup, testing, and PR guidelines.

## License

[Apache License 2.0](./LICENSE) — enterprise-friendly with patent grant.
