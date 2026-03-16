// ─── God Clause: Embeddable AI Governance Framework ──────────────────

export { GodClause } from "./governance";
export type { GovernanceOptions } from "./governance";

// Trust Contracts
export { parseContract, serializeContract, summarizeContract, resolveInheritance } from "./contracts/parser";
export { ContractParseError } from "./contracts/parser";
export { trustContractSchema } from "./contracts/schema";
export { ContractRegistry } from "./contracts/registry";
export { ContractWatcher } from "./contracts/watcher";
export type { WatcherOptions } from "./contracts/watcher";
export { ContractChangeLog } from "./contracts/changelog";
export type { ContractChangeEvent, ContractChangeType, ChangeLogQuery } from "./contracts/changelog";

// Policy Engine
export { PolicyEngine, PolicyViolationError } from "./engine/policy-engine";
export type { PolicyEngineOptions, PolicyHook } from "./engine/policy-engine";
export { evaluateRule, evaluateConditionExpr, resolveField, evaluateOperator, actionMatches } from "./engine/evaluator";
export type { ConditionResult, EvaluatorContext } from "./engine/evaluator";

// State Store (rate limiting)
export { MemoryStateStore, parseISO8601Duration } from "./engine/state-store";
export type { StateStore } from "./engine/state-store";

// Decision Cache
export { DecisionCache } from "./engine/cache";
export type { CacheOptions } from "./engine/cache";

// Audit
export { AuditLog, MemoryAuditSink } from "./audit/audit-log";
export type { AuditSink, AuditLogOptions } from "./audit/audit-log";
export { computeMerkleRoot } from "./audit/seal";
export type { ChainSeal } from "./audit/seal";
export { FileAuditSink } from "./audit/file-sink";
export type { FileSinkOptions } from "./audit/file-sink";
export { TraceBuilder } from "./audit/trace";

// Audit Sinks
export { WebhookAuditSink } from "./audit/sinks/webhook-sink";
export type { WebhookSinkOptions } from "./audit/sinks/webhook-sink";
export { MultiAuditSink } from "./audit/sinks/multi-sink";
export { ImmutableAuditSink, ImmutabilityViolationError } from "./audit/sinks/immutable-sink";

// Audit Export
export { exportAuditCSV, exportAuditJSON, exportAuditSummary } from "./audit/exporter";
export type { AuditSummary } from "./audit/exporter";

// Multi-Tenancy
export { TenantScope } from "./tenancy/tenant";
export type { TenantOptions } from "./tenancy/tenant";

// Middleware
export { godClauseMiddleware } from "./middleware/http";
export type { HttpMiddlewareOptions } from "./middleware/http";
export {
  createAIHook,
  createLangChainCallbackHandler,
  createVercelAIWrapper,
} from "./middleware/ai-sdk";
export type {
  AIInvocationHook,
  AIHookOptions,
  LangChainHandlerOptions,
  VercelAIWrapperOptions,
} from "./middleware/ai-sdk";
export { GovernedStream, createGovernedStream } from "./middleware/streaming";
export type { GovernedStreamOptions } from "./middleware/streaming";

// Server
export { createServer } from "./server/server";
export type { ServerOptions, GodClauseServer } from "./server/server";

// Observability
export { OTelAuditSink } from "./observability/otel-sink";
export type { OTelSinkOptions } from "./observability/otel-sink";
export { Logger } from "./observability/logger";
export type { LogLevel, LoggerOptions } from "./observability/logger";

// Cryptographic Signing
export { signContract, verifyContractSignature, contractFingerprint, paeEncode } from "./crypto/dsse";
export type { DSSEEnvelope, SigningOptions, VerifyOptions } from "./crypto/dsse";
export { requestTimestamp, verifyTimestampConsistency, createLocalTimestamp } from "./crypto/timestamp";
export type { TimestampToken, TimestampRequestOptions } from "./crypto/timestamp";

// Compliance
export { generateComplianceReport } from "./compliance/reporter";
export type { ComplianceReport, ComplianceControl, ComplianceFramework, ControlStatus, ReportOptions } from "./compliance/reporter";
export { TLAPlusGenerator } from "./compliance/tlaplus-generator";

// Notifications
export { WebhookNotifier } from "./notifications/webhook";
export type { WebhookConfig, WebhookEvent } from "./notifications/webhook";

// CLI / Linting
export { lintContract } from "./cli/linter";
export type { LintResult, LintSeverity } from "./cli/linter";

// Zero-Trust Engine Modules
export { MCPRouter } from "./engine/mcp-router";
export { ModelBindingVerifier } from "./engine/model-binding";
export { SecureBoot } from "./engine/boot";
export type { SecureBootOptions } from "./engine/boot";
export { DegradationManager } from "./engine/degradation";
export { HumanOverrideManager, generateEd25519KeyPair, signOverridePayload } from "./engine/human-override";
export { CompiledPolicyEvaluator } from "./engine/compiled-evaluator";

// Sandbox
export { WasmPolicySandbox } from "./sandbox/wasm-sandbox";
export { SandboxedEvaluator } from "./sandbox/vm-sandbox";

// Attestation
export { AttestationService } from "./attestation/rats";
export { SoftwareTrustAnchor, TPMTrustAnchor, SGXTrustAnchor, FirecrackerTrustAnchor, createTrustAnchor, NotImplementedError } from "./attestation/trust-anchor";
export type { TrustAnchor } from "./attestation/trust-anchor";

// Proof Bundle
export { ProofBundleBuilder } from "./audit/proof-bundle";

// Signed Policy Bundles
export { packBundle, signBundle, verifyBundle, unpackBundle, BundleWatcher } from "./contracts/bundle";
export type { PolicyBundle, SignedBundle, BundleWatcherOptions } from "./contracts/bundle";

// Contract Formats
export { parseMarkdownContract } from "./contracts/markdown-parser";
export type { MarkdownSection, MarkdownContractResult } from "./contracts/markdown-parser";
export { P2TGenerator } from "./contracts/p2t-generator";
export type { P2TTemplate, P2TInput, P2TParam } from "./contracts/p2t-generator";

// Types
export type {
  TrustContract,
  ContractMetadata,
  DataGovernance,
  PolicyRule,
  PolicyCondition,
  PolicyConditionLeaf,
  PolicyConditionAll,
  PolicyConditionAny,
  PolicyConditionNot,
  PolicyConditionExpr,
  PolicyContext,
  CallerInfo,
  PolicyDecision,
  RuleEvaluation,
  ViolatedCondition,
  AuditEntry,
  AuditQuery,
  Severity,
  DecisionOutcome,
  DataClass,
  ActionVerb,
  ConditionOperator,
  Obligation,
  GovernanceContext,
  TraceContext,
  SpanType,
  EvaluateOptions,
  RateLimitValue,
  ModelBinding,
  MCPPermission,
  DegradationTier,
  HumanOverride,
  ProofBundle,
  ChainSealRef,
  TimestampRef,
  MCPToolCall,
  MCPAuthResult,
  ModelBindingResult,
  PreFlightResult,
  ProofVerificationResult,
  RuleScope,
  // Plan 2: Sandbox types
  WasmSandboxOptions,
  WasmResourceUsage,
  ObligationResult,
  SandboxOptions,
  // Plan 2: Compiled evaluator types
  CompiledContract,
  CompiledRule,
  CompilationStats,
  // Plan 2: Immutable audit types
  ImmutableSinkOptions,
  IntegrityReport,
  ImmutableStoreStats,
  // Plan 2: TLA+ types
  TLAPlusOptions,
  TLAPlusSpec,
  ModelCheckResult,
  // Plan 2: Attestation types
  AttestationChallenge,
  AttestationEvidence,
  AttestationClaim,
  AttestationResult,
  AttestationPolicy,
  AppraisalResult,
  AttestationOptions,
  // Plan 2: Trust anchor types
  TrustQuote,
  TrustAnchorInfo,
} from "./types";
