// ─── Trust Contract Types ────────────────────────────────────────────

export type Severity = "block" | "warn" | "log" | "modify";
export type DecisionOutcome = "permit" | "deny" | "modify";
export type DataClass = "pii" | "phi" | "financial" | "credentials" | "public" | "internal" | "confidential";
export type ActionVerb =
  | "generate"
  | "classify"
  | "summarize"
  | "translate"
  | "extract"
  | "transform"
  | "decide"
  | "recommend"
  | "*"
  | (string & {});

/** An obligation attached to a modify-severity rule. */
export interface Obligation {
  obligation_id: string;
  type: string;
  params?: Record<string, unknown>;
  source_rule_id: string;
}

/** A single rule inside a trust contract. */
export interface PolicyRule {
  id: string;
  description: string;
  /** The AI action this rule governs. "*" means all actions. */
  action: ActionVerb | ActionVerb[];
  /** Conditions that must hold for the action to proceed. Supports nested AND/OR/NOT logic. */
  conditions: PolicyConditionExpr[];
  /** What happens when a condition is violated. */
  on_violation: Severity;
  /** Optional metadata tags for categorisation. */
  tags?: string[];
  /** Obligations to impose when on_violation is "modify" and conditions fail. */
  obligations?: Array<{ obligation_id: string; type: string; params?: Record<string, unknown> }>;
  /** Human-readable message displayed when the rule is violated. */
  message?: string;
  /** Hazard classification for this rule (e.g. "pii_exposure", "prompt_injection"). */
  hazard_class?: string;
  /** Scope constraints: which models, actions, or data classes this rule applies to. */
  scope?: RuleScope;
  /** Conditions that exempt from this rule (if met, rule is skipped). */
  exceptions?: PolicyConditionExpr[];
  /** Evidence types required for compliance (e.g. "human_review", "model_hash"). */
  required_evidence?: string[];
}

/** Scope constraints for a policy rule. */
export interface RuleScope {
  models?: string[];
  actions?: string[];
  data_classes?: DataClass[];
}

// ─── Condition Types (leaf + composites) ─────────────────────────────

/** A leaf condition that compares a field value. */
export interface PolicyConditionLeaf {
  /** The field path to evaluate (dot-notation). */
  field: string;
  /** The operator for comparison. */
  operator: ConditionOperator;
  /** The value to compare against. */
  value: unknown;
}

/** All child expressions must pass. */
export interface PolicyConditionAll {
  all: PolicyConditionExpr[];
}

/** At least one child expression must pass. */
export interface PolicyConditionAny {
  any: PolicyConditionExpr[];
}

/** The child expression must NOT pass. */
export interface PolicyConditionNot {
  not: PolicyConditionExpr;
}

/** Recursive condition expression: leaf comparison or boolean combinator. */
export type PolicyConditionExpr = PolicyConditionLeaf | PolicyConditionAll | PolicyConditionAny | PolicyConditionNot;

/** @deprecated Use PolicyConditionLeaf instead. Kept for backward compatibility. */
export type PolicyCondition = PolicyConditionLeaf;

export type ConditionOperator =
  | "equals"
  | "not_equals"
  | "contains"
  | "not_contains"
  | "greater_than"
  | "less_than"
  | "in"
  | "not_in"
  | "matches" // regex
  | "exists"
  | "not_exists"
  | "rate_limit";

/** Value shape for rate_limit operator conditions. */
export interface RateLimitValue {
  max: number;
  window: string; // ISO 8601 duration, e.g. "PT1H", "PT5M"
}

/** Top-level trust contract document. */
export interface TrustContract {
  /** Semantic version of the contract schema. */
  schema_version: string;
  /** Human-readable contract metadata. */
  metadata: ContractMetadata;
  /** Data handling declarations. */
  data_governance: DataGovernance;
  /** The enforceable policy rules. */
  rules: PolicyRule[];
  /** Human-readable plain-language summary auto-generated or hand-written. */
  plain_language_summary?: string;
  /** Name of a parent contract to inherit rules from (resolved via ContractRegistry). */
  extends?: string;
  /** Rules that override parent rules with the same ID when using inheritance. */
  override_rules?: PolicyRule[];
  /** Model bindings: allowed AI models with optional SHA-256 hashes and constraints. */
  model_bindings?: ModelBinding[];
  /** MCP tool routing permissions: control which MCP tools can be called. */
  mcp_permissions?: MCPPermission[];
  /** Degradation tiers: progressive capability stripping based on attestation state. */
  degradation_tiers?: DegradationTier[];
}

export interface ContractMetadata {
  name: string;
  version: string;
  author: string;
  description: string;
  effective_date: string;
  review_date?: string;
  stakeholders?: string[];
}

export interface DataGovernance {
  /** Which data classes are permitted as input. */
  allowed_input_classes: DataClass[];
  /** Which data classes are permitted in output. */
  allowed_output_classes: DataClass[];
  /** Maximum retention period in ISO 8601 duration (e.g. "P30D"). */
  retention_period: string;
  /** Whether data may leave the deployment region. */
  cross_border_transfer: boolean;
}

// ─── Runtime Context ─────────────────────────────────────────────────

// ─── Trace Context ──────────────────────────────────────────────────

export type SpanType = "agent_run" | "model_call" | "tool_call" | "tool_result" | "custom";

export interface TraceContext {
  trace_id: string;
  span_id: string;
  parent_span_id?: string;
  span_type?: SpanType;
}

// ─── Governance Context ─────────────────────────────────────────────

export interface GovernanceContext {
  contract_id: string;
  policy_sha256: string;
  model_sha256?: string;
  agent_fingerprint?: string;
}

// ─── Evaluate Options ───────────────────────────────────────────────

export interface EvaluateOptions {
  /** Only evaluate rules with at least one of these tags. */
  includeTags?: string[];
  /** Skip rules that have any of these tags. */
  excludeTags?: string[];
}

/** The runtime context passed into the policy engine for every AI action. */
export interface PolicyContext {
  /** The action being performed. */
  action: ActionVerb;
  /** The input payload (model prompt, data, etc.). */
  input: Record<string, unknown>;
  /** The output payload (model response, result, etc.). May be absent for pre-checks. */
  output?: Record<string, unknown>;
  /** Caller / session metadata. */
  caller: CallerInfo;
  /** Arbitrary additional context. */
  metadata?: Record<string, unknown>;
  /** Distributed trace context for correlating spans. */
  trace?: TraceContext;
}

export interface CallerInfo {
  user_id: string;
  session_id: string;
  roles: string[];
  ip_address?: string;
  tenant_id?: string;
}

// ─── Evaluation Results ──────────────────────────────────────────────

export interface RuleEvaluation {
  rule_id: string;
  rule_description: string;
  passed: boolean;
  severity: Severity;
  violated_conditions: ViolatedCondition[];
  timestamp: string;
  /** Obligations imposed by modify-severity rules. */
  obligations?: Obligation[];
  /** Contract version this rule came from. */
  contract_version?: string;
}

export interface ViolatedCondition {
  field: string;
  operator: ConditionOperator;
  expected: unknown;
  actual: unknown;
}

export interface PolicyDecision {
  /** Unique decision ID for audit linkage. */
  decision_id: string;
  /** Whether the action is allowed to proceed (outcome !== "deny"). */
  allowed: boolean;
  /** Three-valued outcome: permit, deny, or modify (allow with obligations). */
  outcome: DecisionOutcome;
  /** Individual rule evaluations. */
  evaluations: RuleEvaluation[];
  /** Aggregated warnings (severity=warn rules that failed). */
  warnings: RuleEvaluation[];
  /** Aggregated blocks (severity=block rules that failed). */
  blocks: RuleEvaluation[];
  /** Aggregated log entries (severity=log rules that failed). Do not affect allowed. */
  logs: RuleEvaluation[];
  /** Aggregated modify entries (severity=modify rules that failed). */
  modifications: RuleEvaluation[];
  /** All obligations from modify-severity rules that failed. */
  obligations: Obligation[];
  /** ISO timestamp of the decision. */
  timestamp: string;
  /** The original context snapshot. */
  context: PolicyContext;
  /** Governance provenance binding. */
  governance_context?: GovernanceContext;
}

// ─── Audit Types ─────────────────────────────────────────────────────

export interface AuditEntry {
  entry_id: string;
  decision_id: string;
  contract_name: string;
  contract_version: string;
  action: ActionVerb;
  caller: CallerInfo;
  allowed: boolean;
  /** Three-valued outcome. */
  outcome?: DecisionOutcome;
  rule_results: { rule_id: string; passed: boolean; severity: Severity }[];
  warnings: string[];
  blocks: string[];
  logs: string[];
  /** Obligation IDs from modify-severity rules. */
  obligations?: string[];
  /** Tags from evaluated rules. */
  tags?: string[];
  /** Tenant ID if operating in multi-tenant mode. */
  tenant_id?: string;
  /** Trace correlation fields. */
  trace_id?: string;
  span_id?: string;
  parent_span_id?: string;
  /** SHA-256 of the policy rules that produced this decision. */
  policy_sha256?: string;
  timestamp: string;
  /** SHA-256 hash of the previous entry for tamper evidence. */
  prev_hash: string;
  /** SHA-256 hash of this entry. */
  hash: string;
  /** Hash algorithm version for forward compatibility. */
  hash_version: number;
  /** HMAC-SHA256 signature when audit secret key is configured. */
  hmac_signature?: string;
}

export interface AuditQuery {
  from?: string;
  to?: string;
  action?: ActionVerb;
  user_id?: string;
  allowed?: boolean;
  rule_id?: string;
  /** Filter by rule tags. */
  tags?: string[];
  /** Filter by tenant. */
  tenant_id?: string;
  /** Filter by trace ID. */
  trace_id?: string;
  /** Filter by parent span ID. */
  parent_span_id?: string;
  limit?: number;
  offset?: number;
}

// ─── Model Binding Types ────────────────────────────────────────────

/** A model binding that restricts which AI models can be used under a contract. */
export interface ModelBinding {
  /** Model identifier (e.g. "gpt-4-turbo", "claude-3-opus"). */
  model_id: string;
  /** Model provider (e.g. "openai", "anthropic"). */
  provider: string;
  /** SHA-256 hash of the model artifact for integrity verification. */
  sha256?: string;
  /** Actions this model is allowed to perform. If empty/undefined, all actions allowed. */
  allowed_actions?: string[];
  /** Maximum tokens the model may generate under this contract. */
  max_tokens?: number;
  /** Maximum temperature allowed for this model. */
  temperature_max?: number;
}

// ─── MCP Permission Types ───────────────────────────────────────────

/** An MCP tool routing permission rule. */
export interface MCPPermission {
  /** Glob pattern matching tool names (e.g. "file_*", "database.query", "*"). */
  tool_pattern: string;
  /** Whether matching tools are allowed (true) or denied (false). */
  allowed: boolean;
  /** Optional conditions for dynamic allow/deny decisions. */
  conditions?: PolicyConditionExpr[];
  /** Whether human approval is required before execution. */
  require_human_approval?: boolean;
  /** Maximum number of calls to matching tools per session. */
  max_calls_per_session?: number;
  /** Audit level for matching tool calls. */
  audit_level?: "full" | "summary" | "none";
}

// ─── Degradation Tier Types ─────────────────────────────────────────

/** A degradation tier defining progressive capability stripping. */
export interface DegradationTier {
  /** Tier level: 0 = full capability, higher = more restricted. */
  tier: number;
  /** Human-readable tier name (e.g. "full", "reduced", "read-only", "locked"). */
  name: string;
  /** What triggers entry into this tier (e.g. "signature_invalid", "audit_write_failed"). */
  trigger: string;
  /** Actions that are still allowed at this tier. */
  capabilities: string[];
  /** Actions that are blocked at this tier. */
  blocked_actions: string[];
  /** Notification targets (webhook URLs or email addresses). */
  notify?: string[];
}

// ─── Human Override Types ───────────────────────────────────────────

/** A cryptographically signed human override of an automated decision. */
export interface HumanOverride {
  /** Unique override identifier. */
  override_id: string;
  /** The decision being overridden. */
  decision_id: string;
  /** Override action: approve a denied decision, reject a permitted one, or escalate. */
  action: "approve" | "reject" | "escalate";
  /** Human-readable reason for the override. */
  reason: string;
  /** Identifier of the person who authorized the override. */
  overrider_id: string;
  /** Ed25519 signature of the override payload (hex-encoded). */
  signature: string;
  /** Ed25519 public key of the overrider (hex-encoded). */
  public_key: string;
  /** ISO 8601 timestamp of the override. */
  timestamp: string;
}

// ─── Proof Bundle Types ─────────────────────────────────────────────

/** A self-contained evidence bundle for regulatory proof and compliance audits. */
export interface ProofBundle {
  /** Unique bundle identifier. */
  bundle_id: string;
  /** ISO 8601 creation timestamp. */
  created_at: string;
  /** The contract(s) that governed the included decisions. */
  contracts: TrustContract[];
  /** Audit entries included in this bundle. */
  audit_entries: AuditEntry[];
  /** Hash chain verification result at bundle creation time. */
  chain_verification: { valid: boolean; entries_checked: number };
  /** Merkle seals covering the included entries. */
  merkle_seals: ChainSealRef[];
  /** RFC 3161 timestamps if available. */
  timestamps?: TimestampRef[];
  /** Human overrides for included decisions. */
  human_overrides?: HumanOverride[];
  /** Bundle metadata. */
  metadata: { generator: string; version: string };
}

/** Merkle seal reference within a proof bundle. */
export interface ChainSealRef {
  seal_id: string;
  from_entry_id: string;
  to_entry_id: string;
  entry_count: number;
  merkle_root: string;
  timestamp: string;
}

/** Timestamp reference within a proof bundle. */
export interface TimestampRef {
  merkle_root: string;
  tsa_url: string;
  timestamp: string;
  tst_hash: string;
}

// ─── MCP Tool Call Types ────────────────────────────────────────────

/** An MCP tool call to be authorized. */
export interface MCPToolCall {
  /** The name of the MCP tool being called. */
  tool_name: string;
  /** Arguments passed to the tool. */
  arguments: Record<string, unknown>;
  /** Session identifier for rate limiting. */
  session_id: string;
}

/** Result of MCP tool call authorization. */
export interface MCPAuthResult {
  /** Whether the tool call is allowed. */
  allowed: boolean;
  /** Whether human approval is required before execution. */
  require_human_approval: boolean;
  /** Audit level for this tool call. */
  audit_level: "full" | "summary" | "none";
  /** The permission rule that matched (if any). */
  matched_permission?: MCPPermission;
  /** Reason for denial (if not allowed). */
  denial_reason?: string;
}

/** Result of model binding verification. */
export interface ModelBindingResult {
  /** Whether the model is allowed. */
  allowed: boolean;
  /** The matching binding (if found). */
  binding?: ModelBinding;
  /** Reason for denial. */
  reason?: string;
}

/** Pre-flight check result for secure boot. */
export interface PreFlightResult {
  /** Whether the system is ready to operate. */
  ready: boolean;
  /** Individual check results. */
  checks: Array<{ name: string; passed: boolean; detail?: string }>;
  /** Current degradation tier (0 = fully operational). */
  degradation_tier: number;
}

/** Proof bundle verification result. */
export interface ProofVerificationResult {
  /** Whether the entire bundle is valid. */
  valid: boolean;
  /** Hash chain verification. */
  chain_valid: boolean;
  /** Merkle seal verification. */
  seals_valid: boolean;
  /** Individual check details. */
  details: Array<{ check: string; passed: boolean; detail?: string }>;
}

// ─── WASM Sandbox Types ─────────────────────────────────────────────

/** Configuration options for the WASM policy sandbox. */
export interface WasmSandboxOptions {
  /** Maximum WebAssembly memory pages (64KB each). Default: 256 (16MB). */
  maxMemoryPages?: number;
  /** Maximum execution time in milliseconds. Default: 5000. */
  executionTimeoutMs?: number;
  /** Maximum number of loaded modules. Default: 32. */
  maxModules?: number;
}

/** Resource usage statistics for a loaded WASM module. */
export interface WasmResourceUsage {
  /** Current memory usage in bytes. */
  memoryBytes: number;
  /** Total number of evaluations performed. */
  executionCount: number;
  /** Duration of the last execution in milliseconds. */
  lastExecutionMs: number;
}

/** Result of executing an obligation in a sandbox. */
export interface ObligationResult {
  /** Whether the obligation was successfully executed. */
  success: boolean;
  /** Modified output data (if any). */
  modifications?: Record<string, unknown>;
  /** Error message if execution failed. */
  error?: string;
}

// ─── VM Sandbox Types ───────────────────────────────────────────────

/** Configuration options for the VM isolate sandbox. */
export interface SandboxOptions {
  /** Maximum execution time in milliseconds. Default: 1000. */
  timeoutMs?: number;
  /** Extra globals to expose in the sandbox (will be frozen). */
  allowedGlobals?: Record<string, unknown>;
  /** Code generation restrictions. */
  codeGeneration?: { strings: boolean; wasm: boolean };
}

// ─── Compiled Evaluator Types ───────────────────────────────────────

/** A pre-compiled contract for fast evaluation. */
export interface CompiledContract {
  /** Name of the source contract. */
  contractName: string;
  /** Version of the source contract. */
  contractVersion: string;
  /** Compiled rule evaluators. */
  compiledRules: CompiledRule[];
  /** ISO 8601 timestamp of compilation. */
  compiledAt: string;
}

/** A single compiled rule ready for fast evaluation. */
export interface CompiledRule {
  /** Rule ID from the source contract. */
  ruleId: string;
  /** Pre-compiled condition evaluator function. */
  evaluator: (ctx: PolicyContext) => { passed: boolean; violations: ViolatedCondition[] };
  /** Whether this rule has rate_limit conditions (needs async fallback). */
  hasRateLimit: boolean;
  /** Violation severity. */
  severity: Severity;
  /** Rule description. */
  description: string;
  /** Rule tags. */
  tags?: string[];
  /** Pre-compiled action matcher. */
  actionMatcher: (action: string) => boolean;
  /** Original rule obligations (for modify-severity rules). */
  obligations?: Array<{ obligation_id: string; type: string; params?: Record<string, unknown> }>;
}

/** Compilation and benchmark statistics. */
export interface CompilationStats {
  /** Number of rules compiled. */
  rulesCompiled: number;
  /** Time taken to compile in milliseconds. */
  compilationMs: number;
  /** Average evaluation time in nanoseconds (populated after benchmark). */
  avgEvaluationNs?: number;
  /** Average interpretive evaluation time in nanoseconds (populated after benchmark). */
  avgInterpretiveNs?: number;
  /** Speedup factor (interpretive / compiled). */
  speedup?: number;
}

// ─── Immutable Audit Storage Types ──────────────────────────────────

/** Configuration options for the immutable audit sink. */
export interface ImmutableSinkOptions {
  /** Base directory for content-addressed storage. */
  baseDir: string;
  /** Whether to re-hash entries on read to detect tampering. Default: true. */
  verifyOnRead?: boolean;
}

/** Result of an integrity verification scan. */
export interface IntegrityReport {
  /** Whether all entries passed verification. */
  valid: boolean;
  /** Number of entries checked. */
  entriesChecked: number;
  /** Hashes of corrupted entries. */
  corruptEntries: string[];
  /** ISO 8601 timestamp of the verification. */
  timestamp: string;
}

/** Statistics for the immutable store. */
export interface ImmutableStoreStats {
  /** Total number of stored entries. */
  entryCount: number;
  /** Total disk usage in bytes. */
  diskBytes: number;
  /** ISO timestamp of the oldest entry. */
  oldestEntry?: string;
  /** ISO timestamp of the newest entry. */
  newestEntry?: string;
}

// ─── TLA+ Formal Verification Types ────────────────────────────────

/** Configuration options for TLA+ spec generation and model checking. */
export interface TLAPlusOptions {
  /** Path to tla2tools.jar (TLC model checker). */
  tlcPath?: string;
  /** Maximum number of states for TLC to explore. */
  maxStates?: number;
  /** Output directory for generated spec files. */
  outputDir?: string;
}

/** A generated TLA+ specification. */
export interface TLAPlusSpec {
  /** TLA+ module name (derived from contract name). */
  moduleName: string;
  /** Content of the .tla specification file. */
  specContent: string;
  /** Content of the .cfg configuration file. */
  configContent: string;
  /** List of generated invariant names. */
  invariants: string[];
  /** List of generated temporal property names. */
  properties: string[];
}

/** Result of running the TLC model checker. */
export interface ModelCheckResult {
  /** Overall status. */
  status: "passed" | "failed" | "unavailable" | "error";
  /** Number of states explored by TLC. */
  statesExplored?: number;
  /** Counterexample trace if a violation was found. */
  counterexample?: string;
  /** Names of invariants that were checked. */
  invariantsChecked: string[];
  /** Duration of model checking in milliseconds. */
  durationMs?: number;
  /** Raw TLC stdout output. */
  rawOutput?: string;
}

// ─── Attestation Types (RATS RFC 9334) ──────────────────────────────

/** A challenge issued by the Verifier for remote attestation. */
export interface AttestationChallenge {
  /** Hex-encoded 32-byte random nonce. */
  nonce: string;
  /** ISO 8601 timestamp of challenge creation. */
  timestamp: string;
  /** Which components to attest (e.g. "contracts", "audit_chain", "system"). */
  scope?: string[];
  /** Challenge validity window in milliseconds. */
  ttlMs: number;
}

/** Evidence collected by the Attester in response to a challenge. */
export interface AttestationEvidence {
  /** The challenge nonce being responded to. */
  challenge_nonce: string;
  /** ISO 8601 timestamp of evidence collection. */
  timestamp: string;
  /** Individual attestation claims. */
  claims: AttestationClaim[];
  /** Ed25519 signature over canonical claims JSON (hex-encoded). */
  signature: string;
  /** Ed25519 public key of the attester (hex-encoded). */
  public_key: string;
}

/** A single attestation claim (measurement). */
export interface AttestationClaim {
  /** Claim type identifier. */
  type: "contract_hash" | "audit_chain" | "system_state" | "evaluator_hash" | "trust_anchor" | (string & {});
  /** Claim value (structure depends on type). */
  value: unknown;
  /** ISO 8601 timestamp of when the measurement was taken. */
  measurement_timestamp: string;
}

/** Verification result from the Verifier. */
export interface AttestationResult {
  /** Overall attestation status. */
  status: "success" | "failure" | "partial";
  /** Per-claim verification details. */
  verified_claims: Array<{ type: string; verified: boolean; detail?: string }>;
  /** ISO 8601 timestamp of verification. */
  timestamp: string;
  /** The challenge nonce that was verified. */
  nonce: string;
}

/** Policy defining what the Relying Party requires for trust. */
export interface AttestationPolicy {
  /** Claim types that must be present and verified. */
  required_claims: string[];
  /** Expected reference values for claims. */
  reference_values: Record<string, unknown>;
  /** Maximum age of evidence before it's considered stale. */
  max_evidence_age_ms?: number;
}

/** Appraisal result from the Relying Party. */
export interface AppraisalResult {
  /** Whether the attested entity is trusted. */
  trusted: boolean;
  /** Per-claim appraisal details. */
  details: Array<{ claim: string; met: boolean; reason?: string }>;
}

/** Configuration options for the attestation service. */
export interface AttestationOptions {
  /** Ed25519 key pair for signing evidence. */
  signingKeyPair?: { publicKey: string; privateKey: string };
  /** Challenge validity window in milliseconds. Default: 30000. */
  challengeTtlMs?: number;
  /** Claim types that must be collected during attestation. */
  requiredClaims?: string[];
}

// ─── Hardware Trust Anchor Types ────────────────────────────────────

/** A hardware or software attestation quote. */
export interface TrustQuote {
  /** Type of trust anchor that produced this quote. */
  anchorType: string;
  /** Public key of the trust anchor (hex-encoded). */
  publicKey: string;
  /** Nonce used in the quote. */
  nonce: string;
  /** Platform measurements (PCR values or software equivalents). */
  measurements: Record<string, string>;
  /** Signature over the quote content (hex-encoded). */
  signature: string;
  /** ISO 8601 timestamp. */
  timestamp: string;
}

/** Information about a trust anchor's capabilities. */
export interface TrustAnchorInfo {
  /** Trust anchor type (e.g. "software", "tpm", "sgx"). */
  type: string;
  /** Whether this anchor is available on the current platform. */
  available: boolean;
  /** Capabilities supported by this anchor. */
  capabilities: string[];
}
