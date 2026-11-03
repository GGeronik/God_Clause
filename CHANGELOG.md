# Changelog

All notable changes to God Clause are documented in this file.

## [Unreleased]

### Added
- **Regex flags**: a `matches` value may be `/pattern/flags` (`i`, `m`, `s`, `u`); unknown flags are rejected at load
- **Server auth and limits**: `API_TOKEN` / `--api-token` bearer authentication (scheme case-insensitive, constant-time compare) on every endpoint except `/v1/health` and `/v1/ready`; `MAX_BODY_BYTES` (default 1 MiB) request-body cap answered with 413; 10 s header and 30 s request timeouts
- **Chain verification exports**: `canonicalJson`, `hashAuditEntry`, `verifyAuditEntries(entries, key?, { prevHash?, headHash? })`; `audit verify --prev-hash` and `--head`
- **Chain resume**: `auditHeadHash` option and `AuditLog.headHash`; `FileAuditSink.lastHash(path)` reads the head from a file and the REST server resumes from `AUDIT_DIR/audit.jsonl`

### Fixed
- REST server answers 400 for invalid JSON, a context without `action`/`caller`, non-string-array `options.includeTags`/`excludeTags`, a batch item or MCP call missing its fields, malformed URL encoding, a non-date `from`/`to` audit filter, and a non-bundle sent to `/v1/proof-bundle/verify`; 500 responses no longer carry internal error text.
- `/v1/mcp/authorize` shares the server's state store, so `max_calls_per_session` is enforced.
- `ProofBundleBuilder.verify()` checks each seal's range in linear time (a 160 KB bundle used to stall the server for over a minute) and fails a seal whose entries are not in the bundle.
- Helm chart refuses to render without `contracts.configMapName` or with several replicas sharing the audit volume, and quotes inline secret values.
- Helm chart: contracts mount at `/app/contracts`, the secret feeds `AUDIT_HMAC_SECRET` (was `HMAC_SECRET`) and optionally `API_TOKEN`, `CONTRACTS_DIR` is set; the Docker image's `CMD` is environment-driven so `AUDIT_DIR` and `CONTRACTS_DIR` take effect; CLI `serve` flags no longer shadow `PORT`, `CONTRACTS_DIR` and `LOG_LEVEL`.
- A blank `AUDIT_HMAC_SECRET` or `API_TOKEN` environment variable is treated as unset, with a startup warning, instead of refusing to start.
- Hot-reload no longer appends duplicates: `PolicyEngine.loadContract()` replaces a contract with the same name and version, `ContractWatcher` deactivates the version a file provided before when the file changes or is deleted (and reloads the other file when two provide the same contract), and `BundleWatcher` replaces the attached instance's contracts with each new bundle via the new `replaceContracts()`; attaching after the first poll applies the current bundle.
- `loadContractVersion(source, { activate: false })` no longer deactivates a version that is already active.
- Rate-limit counters are scoped per rule; two rules on the same field no longer share one bucket.
- A decision is evaluated, hashed and audited against one snapshot of the contract set, so a reload landing mid-evaluation cannot attribute it to the new policy.
- `evaluate()` denies when no contract is loaded and records that deny; the REST server answers 503 on `/v1/evaluate`, `/v1/enforce`, `/v1/evaluate/batch` and `/v1/mcp/authorize` until a contract is loaded.
- A rule whose evaluation throws (invalid regex, missing or misbehaving `StateStore`) blocks instead of rejecting `evaluate()`; the reason is in `RuleEvaluation.error` and in the audit entry's `rule_results`. `MCPRouter` likewise denies on a permission whose condition throws instead of skipping to the next rule.
- Signed bundles are schema-validated after signature verification; `verifyBundle()` and `unpackBundle()` throw `ContractParseError` on a malformed contract, and an envelope with another `payloadType` is not a valid bundle.
- `parseContract()` and `loadContract()` reject invalid or non-string `matches` patterns, wrong-typed `greater_than`/`less_than`/`in`/`not_in` values, malformed `rate_limit` values (`max` not a positive integer, `window` not a finite positive ISO 8601 duration) and `rate_limit` inside `mcp_permissions`, naming the condition's path.
- Audit hash and HMAC now cover nested fields (`caller`, `rule_results`); the old replacer-array serialization skipped nested keys unless the same name also existed at the top level. `hash_version` is 3; older entries no longer verify.
- `verifyAuditChain()` fails on a missing `hmac_signature` when a key is given, on a first entry not linked to the chain start, and on a last entry that is not the current head.
- `ProofBundleBuilder.verify()` recomputes hashes and HMACs and rejects an empty bundle.
- `GodClause` and `TenantScope` keep the in-memory sink alongside custom `auditSinks`, so verify, query and seal see the entries.
- Entries are normalized to plain JSON before hashing and each sink gets its own copy.
- Sinks receive entries in chain order when decisions overlap, and a failing sink no longer stops delivery to the others.
- `FileAuditSink` terminates a torn last line (crash mid-append) before appending, so the next entry is not fused onto it.
- Empty `auditSecretKey` is rejected; an empty verification key no longer skips HMAC checks.

### Removed

Scaffolding that existed so a README bullet could be true, but did not do what the bullet said. Each item names the defect that made it unsafe to ship.

- `src/sandbox/` (`WasmPolicySandbox`, `SandboxedEvaluator`) — the VM sandbox escaped to `process` in one line; WASM modules could not read the evaluation context
- `src/attestation/` (`AttestationService`, trust anchors) — the evidence signature covered `[{}]` instead of the claims; the verifier accepted any key; every TPM/SGX operation threw
- `src/compliance/tlaplus-generator.ts` (`TLAPlusGenerator`, CLI `tlaplus`) — the generated spec was never passed to TLC
- `src/compliance/reporter.ts` (`generateComplianceReport`) — certified a hash chain it never verified; controls flipped to satisfied on schema-required fields alone
- `src/crypto/timestamp.ts` (`requestTimestamp`) — never parsed or verified the TSA response; the `timestamp` field was the local clock
- `src/contracts/p2t-generator.ts` (`P2TGenerator`, CLI `generate`), `markdown-parser.ts`, `changelog.ts` — not wired into GodClause, the CLI or the server
- `src/engine/human-override.ts` (`HumanOverrideManager`, `POST /v1/override`) — accepted any self-supplied public key
- `src/engine/boot.ts` (`SecureBoot`, CLI `boot`, `GET /v1/boot/preflight`) — swallowed parse errors and reported READY
- `src/engine/degradation.ts` (`DegradationManager`, `GET /v1/degradation`, the `degradation_tiers` contract section) — the `locked` tier blocked nothing
- `src/engine/cache.ts` (`DecisionCache`) — cache key ignored nested fields, so one user's cached decision could be served to another
- `src/engine/compiled-evaluator.ts` (`CompiledPolicyEvaluator`) — passed every rule containing a `rate_limit`
- `dashboard/` and its CI job
- `GET /v1/attestation/status`, `POST /v1/attestation/challenge`, `POST /v1/attestation/verify`, CLI `attest`
- `docs/compliance.md`

### Changed
- `PolicyEngine` (and so `GodClause` and `TenantScope`) uses an in-memory `StateStore` when none is given, so `rate_limit` rules work out of the box; pass a shared store for several processes.
- `evaluate()` applies the loaded contracts' `mcp_permissions` when `metadata.mcp_tool` names a tool (first match wins; no matching or no loaded permission denies): a denied tool blocks under rule id `MCP-PERMISSIONS`, `require_human_approval` becomes a `require_review` obligation, and the decision is audited like any other. `POST /v1/mcp/authorize` goes through `evaluate()` too, so it is audited and answers with `allowed`, `require_human_approval`, `denial_reason`, `decision_id`, `obligations` and `governance_context` (`matched_permission` and `audit_level` are no longer returned).
- `not_contains` fails when the field is missing or not a string/array, so category-based rules fail closed as their headers say.
- Threat contracts: optional signals (`nsfw_score`, `estimated_cost_usd`, the per-type PII flags, the base template's `token_count` and `confidence`) are guarded with `not_exists` so their rules only apply when the field is supplied; required signals still fail closed, and every header now says which is which. `prompt-injection` patterns are case-insensitive, whitespace-tolerant regexes covering disregard/forget/"the above" and verb-anchored extraction phrasings, and a non-string prompt is blocked (`INJ-000`); `cost-control` gained the expensive-model warning its header promised; `mcp-tool-abuse` rules are scoped to `action: mcp_call` so composing it no longer denies every other request, and its audit rule marks every tool invocation; `data-leakage`, `copyright-protection` and the compliance template document every field their rules read.
- Policy hooks (`onDecision`, `onBlock`, `onWarn`, `onLog`) receive the contracts the decision was evaluated against as a second argument.
- README and docs now state that the library computes no detection signals (`output.contains_pii`, `toxicity_score`, `injection_score` are read, never produced) and that the host applies obligations; `examples/openai-wrapper.ts` is the reference
- README comparison table corrected for OPA (arbitrary JSON output, signed bundles), Permit.io (PDP and OPAL are open source) and Guardrails AI (fix/filter/reask outcomes, anonymizing fix actions); RFC 3161 and compliance-report rows dropped
- Removed claims of regulatory admissibility, "no other policy engine does this", and "6 compliance frameworks"

## [2.0.0] - 2026-03-15

### Added
- **Three-valued decisions**: `outcome` field returns `permit`, `deny`, or `modify` (with obligations)
- **Obligations system**: Attach remediation actions (`redact_pii`, `require_review`) to modify-severity rules
- **Rate limiting conditions**: `rate_limit` operator with sliding window counter and pluggable `StateStore`
- **Rule tag filtering**: `includeTags`/`excludeTags` on `evaluate()` and `enforce()` calls
- **Contract versioning**: `ContractRegistry` with `activate()`/`deactivate()` for graceful rollover
- **Multi-tenancy**: `TenantScope` with fully isolated contracts, engine, and audit per tenant
- **Governance context**: SHA-256 policy fingerprint (`policy_sha256`) attached to every decision
- **Trace correlation**: `TraceBuilder` with hierarchical `trace_id`/`span_id`/`parent_span_id`
- **Cross-tenant audit queries**: `queryAllTenantsAudit()` aggregates across all tenants
- **ISO 8601 duration parser**: `parseISO8601Duration()` for rate limit windows

### Changed
- `evaluateRule()` and `evaluateConditionExpr()` are now async (for rate limiting support)
- `PolicyDecision` now includes `outcome`, `modifications`, and `obligations` fields
- `AuditEntry` now includes optional `outcome`, `obligations`, `tags`, `tenant_id`, `trace_id`, `span_id`, `parent_span_id`, `policy_sha256` fields

### Backward Compatibility
- `allowed: boolean` still works — derived from `outcome !== "deny"`
- `evaluate(ctx)` without options still works — `EvaluateOptions` is optional
- `loadContractYAML()` still works — delegates to registry internally

## [1.0.0] - 2026-03-15

### Added
- **Trust contracts**: YAML/JSON policy documents validated against JSON Schema (AJV)
- **Composite conditions**: Recursive AND/OR/NOT boolean logic via `all`/`any`/`not`
- **Policy engine**: Rule evaluation with four severity levels (block, warn, log)
- **12 condition operators**: equals, not_equals, contains, not_contains, greater_than, less_than, in, not_in, matches, exists, not_exists
- **SHA-256 hash chain**: Tamper-evident audit log with linked entry hashes
- **HMAC-SHA256 signing**: Optional secret key for audit entry authentication
- **Merkle seal checkpoints**: Binary Merkle tree for periodic cryptographic snapshots
- **File audit sink**: JSONL append-only with size-based rotation
- **HTTP middleware**: Express/Fastify compatible with auto-block and warning headers
- **AI SDK adapters**: LangChain callback handler, Vercel AI SDK wrapper, generic hooks
- **Plain-language summaries**: Auto-generated human-readable rule descriptions
- **Example contracts**: Healthcare AI, content moderation, financial governance
