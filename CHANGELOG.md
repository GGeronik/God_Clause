# Changelog

All notable changes to God Clause are documented in this file.

## [Unreleased]

### Fixed
- Audit hash and HMAC now cover nested fields (`caller`, `rule_results`); the old replacer-array serialization skipped nested keys unless the same name also existed at the top level. `hash_version` is 3; older entries no longer verify.
- `verifyAuditChain()` fails on a missing `hmac_signature` when a key is given, on a first entry not linked to the chain start, and on a last entry that is not the current head.
- `ProofBundleBuilder.verify()` recomputes hashes and HMACs and rejects an empty bundle.
- `GodClause` and `TenantScope` keep the in-memory sink alongside custom `auditSinks`, so verify, query and seal see the entries.
- Entries are normalized to plain JSON before hashing and each sink gets its own copy.
- Sinks receive entries in chain order when decisions overlap, and a failing sink no longer stops delivery to the others.
- `FileAuditSink` terminates a torn last line (crash mid-append) before appending, so the next entry is not fused onto it.
- Empty `auditSecretKey` is rejected; an empty verification key no longer skips HMAC checks.

### Added
- **Chain verification exports**: `canonicalJson`, `hashAuditEntry`, `verifyAuditEntries(entries, key?, { prevHash?, headHash? })`; `audit verify --prev-hash` and `--head`
- **Chain resume**: `auditHeadHash` option and `AuditLog.headHash`; `FileAuditSink.lastHash(path)` reads the head from a file and the REST server resumes from `AUDIT_DIR/audit.jsonl`

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
