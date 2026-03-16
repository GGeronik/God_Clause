# Architecture

God Clause is a three-layer AI governance chain: **Trust Contracts** define policy, the **Policy Engine** enforces it at runtime, and the **Audit System** proves it happened.

## System Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        Trust Contracts                           │
│                                                                  │
│  YAML/JSON documents with schema-validated, enforceable rules    │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────────────────┐ │
│  │  metadata   │  │ data_govern  │  │  rules (conditions +     │ │
│  │  name, ver  │  │ input/output │  │  severity + obligations) │ │
│  │  author     │  │ retention    │  │  composite AND/OR/NOT    │ │
│  └────────────┘  └──────────────┘  └──────────────────────────┘ │
│                                                                  │
│  Parser (YAML → validated object) │ Registry (versioned store)   │
│  Inheritance (extends → merge)    │ Watcher (hot-reload)         │
└──────────────────────┬───────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                       Policy Engine                              │
│                                                                  │
│  PolicyContext ──► Evaluator ──► PolicyDecision                   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐    │
│  │ For each rule:                                            │    │
│  │  1. Match action verb (or "*" wildcard)                   │    │
│  │  2. Evaluate conditions recursively (leaf / all / any / not)│   │
│  │  3. Classify: block → deny, modify → modify+obligations, │    │
│  │     warn → warning, log → log entry                       │    │
│  │  4. Rate limit conditions → async StateStore lookup       │    │
│  └──────────────────────────────────────────────────────────┘    │
│                                                                  │
│  Three-valued output: permit │ deny │ modify (with obligations)  │
│  Hooks: onDecision, onBlock, onWarn, onLog                       │
│  Tag filtering: includeTags / excludeTags                        │
│  Decision cache: SHA-256(context) → TTL cache                    │
│  Governance context: policy SHA-256 fingerprint per decision     │
└──────────────────────┬───────────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────────┐
│                   Evidence-Grade Audit System                     │
│                                                                  │
│  ┌─────────────────┐   ┌──────────────────┐   ┌──────────────┐ │
│  │   Hash Chain     │   │   Merkle Seals   │   │    Sinks      │ │
│  │  SHA-256 linked  │   │  Binary tree     │   │  Memory       │ │
│  │  HMAC-SHA256     │   │  checkpoints     │   │  File (JSONL) │ │
│  │  tamper-evident  │   │  over segments   │   │  Webhook      │ │
│  └─────────────────┘   └──────────────────┘   │  OTel/OTLP    │ │
│                                                 │  Multi-sink   │ │
│  ┌─────────────────┐   ┌──────────────────┐   └──────────────┘ │
│  │  DSSE Signing    │   │  RFC 3161        │                     │
│  │  Contract auth   │   │  Timestamps      │   Sampling: permit  │
│  │  Ed25519/ECDSA   │   │  External clock  │   rate configurable │
│  └─────────────────┘   └──────────────────┘                     │
│                                                                  │
│  Queries: user, action, tenant, trace, tags, date range, rule_id │
└──────────────────────────────────────────────────────────────────┘
```

## Deployment Modes

God Clause targets **Cloud, Serverless, and Enterprise Platform Engineering** environments.

### 1. Embedded Library (TypeScript/Node.js)

The simplest mode. Import `GodClause`, load contracts, call `evaluate()`. No server, no network calls.

```typescript
import { GodClause } from "god-clause";
const gov = new GodClause();
gov.loadContractYAML(contractYAML);
const decision = await gov.evaluate(context);
```

**Best for**: TypeScript applications, Vercel AI SDK, LangChain, single-service architectures.

### 2. Standalone REST API (Policy Decision Point)

Run as a standalone server that any language can call via HTTP.

```
┌─────────────────┐     ┌─────────────────┐
│  Python/Go/Java │────►│  God Clause PDP  │
│  Application    │◄────│  :3000           │
└─────────────────┘     └─────────────────┘
                         POST /v1/evaluate
                         GET  /v1/metrics
                         GET  /v1/events (SSE)
```

**Best for**: Polyglot environments, microservices, teams that want centralized policy management.

### 3. Kubernetes Sidecar

Deploy alongside each service using the Helm chart. Contracts loaded from ConfigMap, auto-reloaded on change.

```
┌─────────────────────────────────────┐
│  Pod                                │
│  ┌──────────────┐  ┌────────────┐  │
│  │  Your Service │──│ God Clause │  │
│  │              │  │  Sidecar   │  │
│  └──────────────┘  └────────────┘  │
│                     ▲               │
│          ConfigMap ─┘               │
└─────────────────────────────────────┘
```

**Best for**: Platform engineering teams, Kubernetes-native organizations, multi-team policy governance.

### 4. Serverless (Lambda / Cloud Functions)

Import the library directly in serverless functions. The lightweight dependency tree (4 packages) keeps cold starts fast.

```typescript
export const handler = async (event) => {
  const gov = new GodClause();
  gov.loadContractYAML(contractYAML);
  const decision = await gov.evaluate(buildContext(event));
  if (decision.outcome === "deny") return { statusCode: 403 };
  // proceed with governed response
};
```

**Best for**: Event-driven architectures, per-request governance, pay-per-use cost models.

## Data Flow

### Single Decision

```
1. Application calls gov.evaluate(context)
2. PolicyEngine iterates active contracts
3. For each contract, rules are filtered by:
   - Action verb match
   - Tag inclusion/exclusion (if EvaluateOptions provided)
4. Each rule's conditions are evaluated recursively:
   - Leaf conditions: field lookup → operator comparison
   - Composite: all (AND), any (OR), not (NOT)
   - Rate limit: async StateStore.recordAndCount()
5. Failed conditions are classified by severity:
   - block → deny decision
   - modify → modify decision + obligations collected
   - warn → warning (decision still permits)
   - log → logged but no effect on decision
6. PolicyDecision returned with:
   - outcome: permit | deny | modify
   - obligations: from all modify-severity failures
   - governance_context: { policy_sha256 }
7. onDecision hook fires → AuditLog.record()
8. AuditEntry created with:
   - SHA-256 hash of all fields (sorted keys)
   - prev_hash linking to previous entry
   - Optional HMAC-SHA256 signature
9. Entry appended to all configured sinks
   - Permit decisions may be sampled (permitSampleRate)
   - Deny/modify decisions are ALWAYS recorded
```

### Hash Chain Integrity

```
Entry 1                Entry 2                Entry 3
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ prev_hash: 0 │      │ prev_hash:   │      │ prev_hash:   │
│ ...fields... │──────│ hash(E1)     │──────│ hash(E2)     │
│ hash: H1     │      │ ...fields... │      │ ...fields... │
│ hmac: S1     │      │ hash: H2     │      │ hash: H3     │
└──────────────┘      │ hmac: S2     │      │ hmac: S3     │
                      └──────────────┘      └──────────────┘

Verification:
- Recompute each hash from entry fields (excluding hash + hmac)
- Verify each prev_hash matches prior entry's hash
- If HMAC key provided, verify each hmac_signature
- Any mismatch → tampering detected at that index
```

### Evidence Stack

```
Trust Contract (YAML)
  │ DSSE signature → proves WHO authored it
  ▼
Policy Engine evaluates context
  │ policy_sha256 → proves WHICH contract version was used
  ▼
Audit Entry recorded
  │ SHA-256 hash chain → proves NO TAMPERING
  │ HMAC signature → proves NO RECOMPUTATION
  ▼
Merkle Seal checkpoint
  │ Compact proof of segment integrity
  ▼
RFC 3161 Timestamp
  │ External clock → proves WHEN it happened
  ▼
Evidence-grade proof for regulators
```

## Module Dependencies

```
governance.ts (GodClause)
├── contracts/parser.ts (parseContract, resolveInheritance)
├── contracts/registry.ts (ContractRegistry)
├── contracts/schema.ts (trustContractSchema + AJV)
├── contracts/watcher.ts (ContractWatcher — hot-reload)
├── contracts/changelog.ts (ContractChangeLog)
├── engine/policy-engine.ts (PolicyEngine)
│   ├── engine/evaluator.ts (evaluateRule, evaluateConditionExpr)
│   │   └── engine/state-store.ts (StateStore, MemoryStateStore)
│   └── engine/cache.ts (DecisionCache)
├── audit/audit-log.ts (AuditLog, MemoryAuditSink)
│   ├── audit/seal.ts (computeMerkleRoot)
│   ├── audit/file-sink.ts (FileAuditSink)
│   ├── audit/sinks/webhook-sink.ts (WebhookAuditSink)
│   └── audit/sinks/multi-sink.ts (MultiAuditSink)
├── audit/trace.ts (TraceBuilder)
├── audit/exporter.ts (CSV, JSON, Summary export)
├── crypto/dsse.ts (DSSE contract signing)
├── crypto/timestamp.ts (RFC 3161 timestamps)
├── compliance/reporter.ts (ComplianceReport generator)
├── tenancy/tenant.ts (TenantScope)
├── notifications/webhook.ts (WebhookNotifier)
├── observability/otel-sink.ts (OTelAuditSink)
├── observability/logger.ts (Structured JSON Logger)
├── server/server.ts (REST API PDP)
├── middleware/http.ts (Express/Fastify middleware)
└── middleware/ai-sdk.ts (LangChain, Vercel AI, generic hooks)
```

## Key Design Decisions

1. **YAML over Rego/DSL**: Trust contracts are YAML because non-engineers (legal, compliance, ethics boards) need to read and review them. Rego is powerful but opaque to non-developers.

2. **Three-valued decisions**: Binary allow/deny is too rigid for AI governance. "Modify" means "allow, but with obligations" — e.g., redact PII before returning, require human review before acting. No other open-source policy engine provides this.

3. **Evidence-grade audit**: Five layers of cryptographic evidence (hash chain, HMAC, Merkle seals, DSSE, RFC 3161), each solving a different trust problem. Standard database logs fail regulatory non-repudiation tests; this stack doesn't. See [Evidence-Grade Audit](./evidence-grade-audit.md).

4. **Pluggable everything**: Audit sinks, state stores, and middleware are all interfaces. The core ships with memory/file implementations; production deployments plug in Redis, S3, webhooks, etc.

5. **Minimal dependencies**: Four runtime packages (yaml, ajv, uuid, commander). The core evaluation engine is pure TypeScript with zero external deps. Cold starts in serverless are fast.

6. **Contract inheritance**: Base contracts define organization-wide safety rules. Teams extend them with domain-specific policies. The `extends` field resolves at load time, merging parent and child rules with override support.

7. **Audit sampling**: At high throughput (1000+ decisions/sec), permit decisions can be sampled while deny/modify decisions are always logged. This balances performance with complete violation capture.

8. **Multi-tenancy as first-class**: Each tenant gets isolated contracts, engine, and audit — not just a filter parameter. This prevents cross-tenant data leakage by design.
