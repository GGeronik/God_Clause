# God Clause

**Embeddable TypeScript policy decision point** — YAML rules in, permit / deny / modify decisions out, every decision on a verifiable hash-chained audit log. Bring your own detectors.

> A decision is permit, deny, or **modify**. A modify decision carries obligations (redact PII, add a disclaimer, truncate) that your application applies. Every decision is SHA-256 hash-chained; policies can be DSSE-signed.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20-green.svg)]()
[![TypeScript](https://img.shields.io/badge/TypeScript-5.7-blue.svg)]()
[![CI](https://github.com/GGeronik/God_Clause/actions/workflows/ci.yml/badge.svg)](https://github.com/GGeronik/God_Clause/actions/workflows/ci.yml)

---

## See It Work: A Modify Decision

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

// Your PII detector flagged the LLM output; pass its signal in as output.contains_pii
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

God Clause did not detect the SSN and did not rewrite the string. Your detector set `contains_pii`; your code applies the `redact_pii` obligation. The library evaluated the rule, returned a modify decision with the obligation attached, and recorded the decision on a hash-chained, HMAC-signable, Merkle-sealable audit log. [`examples/openai-wrapper.ts`](./examples/openai-wrapper.ts) is the reference pattern: a detector feeding the engine, and the obligation being applied to the response.

Obligations on a decision are the XACML model, and NeMo Guardrails and Guardrails AI rewrite outputs too. The difference is the packaging: one four-dependency Node package that combines a policy engine, a hash-chained + HMAC + Merkle-sealed audit log, and DSSE-signed policies.

---

## Why God Clause?

### For developers: a policy decision point you embed

| What you get | How |
|---|---|
| Three-valued decisions | `on_violation: block`, `warn`, `log` or `modify` per rule |
| Obligations on modify | Any `type` you define (`redact_pii`, `add_disclaimer`, ...) with `params`; your code applies them |
| Rules over your detector signals | Conditions on fields you set, such as `output.contains_pii`, `input.injection_score`, `output.toxicity_score` |
| Rate limiting | Built-in sliding window per user/org |
| Audit trail | Every decision hash-chained, optionally HMAC-signed and Merkle-sealed |

The library computes no detection signals. It reads fields you place on `input`, `output`, `caller` and `metadata`. PII, toxicity and injection detection are your job, and so is applying obligations. [`examples/openai-wrapper.ts`](./examples/openai-wrapper.ts) shows both ends.

No sidecars. No external services. `npm install god-clause` and write a YAML file.

### For security and compliance reviewers

The audit log is tamper-evident; it is not a compliance product. God Clause records each decision with the SHA-256 of the policy that produced it, chains entries by hash, and can sign entries with HMAC and seal segments with a Merkle root. It generates no compliance reports and certifies nothing against any framework. [docs/evidence-grade-audit.md](./docs/evidence-grade-audit.md) states what each layer proves and what it does not.

---

## Why Trust Contracts Are Not Config Files

A Trust Contract is a YAML file — but it's not "just configuration."

The SHA-256 of the policy is recorded in every audit entry (`governance_context.policy_sha256`), so each decision is tied to the exact policy version that produced it. Change the contract later and the entries made under the old version still carry the old fingerprint.

Add a DSSE signature to record who authored each policy version. The result is a policy document with a verifiable author and a verifiable link to every decision it governed, which is more than a config file.

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
│                     Audit Trail                      │
│  SHA-256 hash chain · HMAC-SHA256 signing            │
│  Merkle seals · policy SHA-256 per entry · OTel      │
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

## Audit Trail: What Each Layer Proves

A plain database log can be edited by anyone with write access and leaves no trace. God Clause's audit log makes edits detectable:

| Layer | What it proves |
|---|---|
| **SHA-256 hash chain** | Each entry links to the previous. Delete or modify any entry → chain breaks → tampering detected |
| **HMAC-SHA256 signing** | Even if someone recomputes hashes, they need the secret key |
| **Merkle seal checkpoints** | O(log n) verification over audit segments |
| **DSSE contract signatures** | Cryptographic proof of who authored each policy |

What it does not give you: an external clock (entry timestamps come from the host), or any proof of what your application did with the decision. Keep the HMAC key away from whoever can write to the log, or the HMAC layer proves nothing.

---

## Threat Contracts

Pre-built contracts for common AI threats. Each reads detector signals that your application sets on the context; the header comment in each file lists the fields it expects. Copy into your project and load:

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

Obligations follow the XACML permit-with-obligations model. What God Clause adds is the audit chain and signed policies in the same small package.

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
- **OpenTelemetry export** — OTLP/HTTP log mapping for Datadog/Grafana/New Relic
- **Prometheus metrics** — `godclause_decisions_total`, `godclause_blocks_total`, evaluation duration histograms
- **REST API server** — standalone PDP with 17 endpoints, SSE streaming, batch evaluation
- **CLI tool** — `validate`, `lint`, `summarize`, `diff`, `evaluate`, `serve`, `audit verify/export`, `init`, `proof-bundle`, `verify-bundle`
- **MCP tool authorization** — glob-matched, fail-closed routing for Model Context Protocol tool calls

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
| Decision outcomes | permit / deny / modify with obligations | Any JSON document; obligations and rewrites are expressible | allow / deny | pass / fix / filter / reask per validator |
| Output rewriting | Obligations returned to the caller, who applies them | Policy can return a rewritten document; caller applies it | No | Built-in fix actions, including anonymizing validators |
| Detection (PII, toxicity, injection) | Bring your own; the engine reads your signals | Bring your own | No | Built-in validator hub |
| Policy format | YAML | Rego | UI, Rego or Cedar via OPAL | Python validators / RAIL |
| Audit integrity | SHA-256 chain + HMAC + Merkle seals | Decision logs, no chain | Decision logs | No |
| Signed policies | DSSE envelopes | Signed bundles | Via OPA bundles | No |
| Rate limiting | Built-in | External | Built-in | No |
| Multi-tenancy | Isolated scopes | Namespaces | Built-in | No |
| Embeddable (no server needed) | Yes | Go library or WASM | PDP runs as a container | Yes |
| Runtime dependencies | 4 | Go binary | PDP + OPAL containers | Many |
| Open-source license | Apache 2.0 | Apache 2.0 | PDP and OPAL are open source; control plane is a hosted service | Apache 2.0 |

---

## The Adoption Path

**Who it's for**: Platform engineering teams building internal GenAI applications who already run (or will build) detectors and want one place to turn those signals into enforced, audited decisions.

**Day 1**: `npm install god-clause`. Load `pii-redaction.contract.yaml`. Wrap your LLM calls, pass your PII detector's result in as `output.contains_pii`, apply the obligation the decision returns. Every decision is hash-chained.

**Week 1**: Add `prompt-injection.contract.yaml` and `toxic-content.contract.yaml`. Set up the REST API server so your Python services can call it too.

**Month 1**: Deploy as a Kubernetes sidecar. Connect Prometheus metrics to Grafana. Seal the audit chain on a schedule and export a proof bundle.

**Quarter 1**: Multi-tenancy for different product teams. DSSE-signed contracts in your policy repo, hot-reloaded as signed bundles.

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

- **[Quick Start](./examples/quickstart.ts)** — 30-line modify decision with audit verification
- **[OpenAI Wrapper](./examples/openai-wrapper.ts)** — Governance around OpenAI calls
- **[Claude Wrapper](./examples/anthropic-wrapper.ts)** — Governance around Anthropic Claude calls
- **[Gemini Wrapper](./examples/gemini-wrapper.ts)** — Governance around Google Gemini calls
- **[MCP Agent Demo](./examples/mcp-agent-demo.ts)** — MCP tool authorization with fail-closed routing
- **[Threat Contracts](./examples/threats/)** — 9 contracts for common AI threats; you supply the detector signals
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
