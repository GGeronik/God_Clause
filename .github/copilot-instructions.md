# GitHub Copilot Instructions — God Clause

## Project
God Clause is an embeddable AI governance framework. YAML trust contracts define rules enforced by a three-valued policy engine (permit/deny/modify). The "modify" outcome attaches obligations (redact PII, add disclaimers) instead of blocking.

## Tech Stack
- TypeScript strict mode, CommonJS, ES2022 target, Node >= 20
- 4 dependencies: ajv, commander, uuid, yaml
- Testing: vitest (504 tests across 35 files)
- Linting: eslint + prettier

## Key Files
- `src/governance.ts` — Main GodClause class
- `src/types.ts` — ALL type definitions (single source of truth)
- `src/index.ts` — ALL public exports
- `src/engine/policy-engine.ts` — Core evaluation loop
- `src/engine/evaluator.ts` — Condition operators (equals, contains, matches, etc.)
- `src/contracts/parser.ts` — YAML/JSON contract parsing
- `src/audit/audit-log.ts` — AuditSink interface + hash chain

## Code Style
- All types must be defined in `src/types.ts`, not inline
- All public APIs must be exported from `src/index.ts`
- No new npm dependencies — use Node.js built-ins
- No `any` in source files
- No `new Function()` or `eval()` — use closure composition
- Test files go in `tests/{module}.test.ts` using vitest describe/it/expect

## Domain Concepts
- **TrustContract**: YAML with schema_version, metadata, data_governance, rules
- **PolicyDecision**: outcome is "permit" | "deny" | "modify", with obligations array
- **Obligation**: `{ type: "redact_pii", params: { replacement: "[REDACTED]" } }`
- **AuditSink**: interface with `append(entry: AuditEntry)` method
- **MCPRouter**: fail-closed MCP tool authorization with glob patterns
- **DSSE**: Dead Simple Signing Envelope for contract signing
