# God Clause — AI Assistant Context

## What This Is

Embeddable AI governance framework. Define guardrails in YAML trust contracts, enforce them at runtime with a three-valued policy engine (permit / deny / **modify**), prove compliance with evidence-grade audit trails. Unlike OPA's binary allow/deny, the "modify" outcome lets you fix outputs (redact PII, add disclaimers) instead of blocking them.

## Commands

```bash
npm test              # 504 tests via vitest — must all pass
npm run build         # tsc → dist/
npm run lint          # eslint — zero errors required (warnings OK)
npm run format        # prettier — run before committing
npx tsc --noEmit      # type-check without emitting dist/
```

## Architecture

```
src/
├── governance.ts              # GodClause class — main entry point
├── types.ts                   # ALL type definitions (~200 types) — single source of truth
├── index.ts                   # Public API — every export goes here
│
├── engine/                    # Policy evaluation
│   ├── policy-engine.ts       #   PolicyEngine: evaluate rules → PolicyDecision
│   ├── evaluator.ts           #   Interpretive condition evaluator (12 operators)
│   ├── compiled-evaluator.ts  #   Closure-compiled evaluator (sub-ms)
│   ├── mcp-router.ts          #   MCP tool authorization (glob match, fail-closed)
│   ├── state-store.ts         #   Rate limiting (MemoryStateStore)
│   ├── cache.ts               #   LRU decision cache
│   ├── boot.ts                #   Secure boot pre-flight checks
│   ├── degradation.ts         #   Graceful degradation tiers
│   ├── human-override.ts      #   Ed25519-signed human overrides
│   └── model-binding.ts       #   Model allowlist/denylist verification
│
├── contracts/                 # Trust contract management
│   ├── parser.ts              #   Parse YAML/JSON, validate, serialize, summarize
│   ├── schema.ts              #   AJV JSON Schema for TrustContract
│   ├── registry.ts            #   Named contract registry with versioning
│   ├── watcher.ts             #   Directory watcher for zero-downtime hot-reload
│   ├── bundle.ts              #   Signed policy bundles (DSSE) + BundleWatcher
│   ├── changelog.ts           #   Contract change tracking
│   ├── markdown-parser.ts     #   Parse contracts from Markdown
│   └── p2t-generator.ts       #   Prompt-to-Trust contract generator
│
├── audit/                     # Evidence-grade audit system
│   ├── audit-log.ts           #   SHA-256 hash chain + AuditSink interface
│   ├── seal.ts                #   Merkle tree seals
│   ├── proof-bundle.ts        #   Court-grade evidence bundles
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
│   └── streaming.ts           #   Buffer-and-release streaming PII interceptor
│
├── server/server.ts           # Standalone REST API (24 endpoints + SSE)
├── attestation/               # IETF RATS RFC 9334 + trust anchors
├── sandbox/                   # WASM + V8 isolate sandboxes
├── crypto/                    # DSSE signing + RFC 3161 timestamps
├── compliance/                # TLA+ generator + compliance reporter (6 frameworks)
├── observability/             # OpenTelemetry sink + structured logger
├── tenancy/                   # Multi-tenant isolation
├── notifications/             # Webhook notifier
└── cli/                       # CLI: validate, lint, evaluate, serve, audit, attest

examples/
├── openai-wrapper.ts          # OpenAI pre/post-check + PII redaction
├── anthropic-wrapper.ts       # Claude wrapper (same pattern)
├── gemini-wrapper.ts          # Gemini wrapper (same pattern)
├── mcp-agent-demo.ts          # MCP tool governance demo
├── quickstart.ts              # 30-line minimal example
├── demo.ts                    # Full feature walkthrough
├── threats/                   # 9 drop-in threat contracts (PII, injection, etc.)
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
Contracts are validated by AJV against the schema in `src/contracts/schema.ts`. Required sections: `schema_version`, `metadata`, `data_governance`, `rules`. Optional: `mcp_permissions`, `model_bindings`, `degradation_tiers`.

### PolicyDecision three-valued outcome
```typescript
type DecisionOutcome = "permit" | "deny" | "modify";
// "modify" carries obligations: { type: "redact_pii", params: { replacement: "[REDACTED]" } }
```

### No new npm dependencies
All features use Node.js built-ins: `crypto`, `vm`, `WebAssembly`, `worker_threads`, `fs`, `child_process`. Current deps: ajv, commander, uuid, yaml.

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
- Use `new Function()` or `eval()` — use closure composition (see `compiled-evaluator.ts`)
- Commit `.env`, `.pem`, `.key`, or credential files
- Use Node 18 — minimum is Node 20 (vitest 3.x requires it)

## Project Metadata

- **License**: Apache-2.0
- **Node**: >= 20
- **Module**: CommonJS (ES2022 target)
- **Dependencies**: 4 (ajv, commander, uuid, yaml)
- **Tests**: 504 across 35 test files
- **GitHub**: https://github.com/GGeronik/God_Clause
