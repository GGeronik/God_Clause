# Changelog

All notable changes to God Clause are documented in this file.

## [Unreleased]

### Added
- **Chain verification exports**: `canonicalJson`, `hashAuditEntry`, `verifyAuditEntries(entries, key?, { prevHash?, headHash? })`; `audit verify --prev-hash` and `--head`
- **Chain resume**: `auditHeadHash` option and `AuditLog.headHash`; `FileAuditSink.lastHash(path)` reads the head from a file and the REST server resumes from `AUDIT_DIR/audit.jsonl`

### Fixed
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
