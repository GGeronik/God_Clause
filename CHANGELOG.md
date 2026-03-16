# Changelog

All notable changes to God Clause are documented in this file.

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
