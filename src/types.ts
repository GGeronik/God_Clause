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

/** End anchors for verifying a run of audit entries. */
export interface AuditChainAnchors {
  /** Expected prev_hash of the first entry. */
  prevHash?: string;
  /** Expected hash of the last entry. */
  headHash?: string;
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
