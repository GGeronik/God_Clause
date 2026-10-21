# God Clause — AI Assistant Context

## What This Is

Embeddable TypeScript policy decision point for AI applications. Define guardrails in YAML trust contracts, enforce them at runtime with a three-valued policy engine (permit / deny / **modify**), and record every decision on a hash-chained audit log. Unlike OPA's binary allow/deny, the "modify" outcome returns obligations (redact PII, add disclaimers) that the host application applies.

The library computes no detection signals. Fields such as `output.contains_pii`, `output.toxicity_score` and `input.injection_score` are read from the context the host supplies; the host runs the detectors and applies the obligations. `examples/openai-wrapper.ts` is the reference pattern.

## Commands

```bash
npm test              # 267 tests via vitest — must all pass
npm run build         # tsc → dist/
npm run lint          # eslint — zero errors required (warnings OK)
npm run format        # prettier — run before committing
npx tsc --noEmit      # type-check without emitting dist/
```

## Architecture

```
src/
├── governance.ts              # GodClause class — main entry point
├── types.ts                   # ALL type definitions — single source of truth
├── index.ts                   # Public API — every export goes here
│
├── engine/                    # Policy evaluation
│   ├── policy-engine.ts       #   PolicyEngine: evaluate rules → PolicyDecision
│   ├── evaluator.ts           #   Condition evaluator (12 operators)
│   ├── mcp-router.ts          #   MCP tool authorization (glob match, fail-closed)
│   ├── state-store.ts         #   Rate limiting (MemoryStateStore)
│   └── model-binding.ts       #   Model allowlist/denylist verification
│
├── contracts/                 # Trust contract management
│   ├── parser.ts              #   Parse YAML/JSON, validate, serialize, summarize
│   ├── schema.ts              #   AJV JSON Schema for TrustContract
│   ├── registry.ts            #   Named contract registry with versioning
│   ├── watcher.ts             #   Directory watcher for zero-downtime hot-reload
│   └── bundle.ts              #   Signed policy bundles (DSSE) + BundleWatcher
│
├── audit/                     # Audit system
│   ├── audit-log.ts           #   SHA-256 hash chain + AuditSink interface
│   ├── seal.ts                #   Merkle tree seals
│   ├── proof-bundle.ts        #   Contracts + entries + seals in one verifiable JSON
│   ├── trace.ts               #   Distributed tracing spans
│   ├── exporter.ts            #   CSV/JSON/summary export
│   ├── file-sink.ts           #   Append-only file audit sink
│   └── sinks/
│       ├── webhook-sink.ts    #   Webhook forwarding
│       ├── multi-sink.ts      #   Fan-out to multiple sinks
│       └── immutable-sink.ts  #   Content-addressed write-once storage
│
├── middleware/                 # Framework integrations
│   ├── http.ts                #   Express/Koa HTTP middleware
│   ├── ai-sdk.ts              #   LangChain, Vercel AI SDK hooks
│   └── streaming.ts           #   Buffer-and-release streaming interceptor
│
├── server/server.ts           # Standalone REST API (17 endpoints incl. SSE)
├── crypto/dsse.ts             # DSSE contract signing
├── observability/             # OpenTelemetry sink + structured logger
├── tenancy/                   # Multi-tenant isolation
├── notifications/             # Webhook notifier
└── cli/                       # CLI: validate, lint, summarize, diff, evaluate, audit, serve, init, proof-bundle, verify-bundle

examples/
├── openai-wrapper.ts          # OpenAI pre/post-check + host-side PII detection and redaction
├── anthropic-wrapper.ts       # Claude wrapper (same pattern)
├── gemini-wrapper.ts          # Gemini wrapper (same pattern)
├── mcp-agent-demo.ts          # MCP tool governance demo
├── quickstart.ts              # 30-line minimal example
├── demo.ts                    # Full feature walkthrough
├── threats/                   # 9 threat contracts (host supplies the detector signals)
└── templates/                 # Base safety/compliance contract templates
```

## Key Patterns

### Types live in one file
All interfaces and types go in `src/types.ts`. Never define types inline in modules. Import from `"../types"`.

### Exports go through index.ts
Every public class, function, and type must be exported from `src/index.ts`. If it's not there, it's not public API.

### AuditSink interface
All audit sinks implement `AuditSink` from `src/audit/audit-log.ts`:
```typescript
interface AuditSink { append(entry: AuditEntry): void | Promise<void>; }
```

### TrustContract schema
Contracts are validated by AJV against the schema in `src/contracts/schema.ts`. Required sections: `schema_version`, `metadata`, `data_governance`, `rules`. Optional: `extends`, `override_rules`, `mcp_permissions`, `model_bindings`.

### PolicyDecision three-valued outcome
```typescript
type DecisionOutcome = "permit" | "deny" | "modify";
// "modify" carries obligations: { type: "redact_pii", params: { replacement: "[REDACTED]" } }
// The host applies obligations; the library only returns them.
```

### No new npm dependencies
All features use Node.js built-ins: `crypto`, `fs`, `http`, `path`. Current deps: ajv, commander, uuid, yaml.

### TypeScript strict mode
Zero type errors required. Avoid `any` in source files. Tests may use `any` sparingly.

### Test conventions
- Files: `tests/{module-name}.test.ts`
- Framework: vitest with `describe`/`it`/`expect`
- Run single test: `npx vitest run tests/{name}.test.ts`

## Common Tasks

### Add a new source module
1. Create `src/{category}/{name}.ts`
2. Add types to `src/types.ts`
3. Export from `src/index.ts`
4. Create `tests/{name}.test.ts`
5. Verify: `npx tsc --noEmit && npx vitest run`

### Add a new threat contract
1. Create `examples/threats/{name}.contract.yaml`
2. Include header comment block explaining what fields the app must set
3. Add row to `examples/threats/README.md` catalog table
4. Follow the pattern of existing contracts (e.g., `pii-redaction.contract.yaml`)

### Add a new LLM wrapper example
1. Copy `examples/openai-wrapper.ts` as template
2. Change the response interface and `callLLM()` to match the provider's API shape
3. Update text extraction logic for that provider
4. Keep the same contract YAML, `detectPII`, `applyRedaction`, and decision handling
5. Add production SDK usage in comments

### Add a new audit sink
1. Create `src/audit/sinks/{name}-sink.ts`
2. Implement the `AuditSink` interface (`append` method)
3. Export from `src/index.ts`
4. See `webhook-sink.ts` or `immutable-sink.ts` for reference

## Do NOT

- Add npm dependencies — use Node.js built-ins
- Define types outside `src/types.ts`
- Skip `src/index.ts` exports for public APIs
- Use `new Function()` or `eval()`
- Claim the library detects PII, toxicity or injection, or that it applies obligations — the host does both
- Commit `.env`, `.pem`, `.key`, or credential files
- Use Node 18 — minimum is Node 20 (vitest 3.x requires it)

## Project Metadata

- **License**: Apache-2.0
- **Node**: >= 20
- **Module**: CommonJS (ES2022 target)
- **Dependencies**: 4 (ajv, commander, uuid, yaml)
- **Tests**: 267 across 23 test files
- **GitHub**: https://github.com/GGeronik/God_Clause
