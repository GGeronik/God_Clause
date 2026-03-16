import type {
  MCPPermission,
  MCPToolCall,
  MCPAuthResult,
  PolicyConditionExpr,
  PolicyContext,
} from "../types";
import { evaluateConditionExpr } from "./evaluator";
import type { StateStore } from "./state-store";

// ─── Glob Matcher ───────────────────────────────────────────────────

/**
 * Simple glob matcher supporting `*` wildcards.
 * - `*` matches any sequence of characters (including empty).
 * - `file_*` matches `file_read`, `file_write`, `file_`, etc.
 * - `database.query` matches exactly `database.query`.
 * - `*` alone matches everything.
 *
 * Uses a greedy approach: each `*` segment matches as much as possible
 * while still allowing subsequent literal segments to match.
 */
export function globMatch(pattern: string, value: string): boolean {
  // Fast paths
  if (pattern === "*") return true;
  if (pattern === value) return true;
  if (!pattern.includes("*")) return pattern === value;

  // Split pattern on `*` to get literal segments
  const segments = pattern.split("*");
  let pos = 0;

  // First segment must match at the start
  const first = segments[0];
  if (!value.startsWith(first)) return false;
  pos = first.length;

  // Last segment must match at the end
  const last = segments[segments.length - 1];
  if (!value.endsWith(last)) return false;

  // If there's only one `*`, we just need start + end check
  // but also verify no overlap
  if (segments.length === 2) {
    return value.length >= first.length + last.length;
  }

  // Middle segments must appear in order
  for (let i = 1; i < segments.length - 1; i++) {
    const seg = segments[i];
    if (seg === "") continue; // consecutive `*`s
    const idx = value.indexOf(seg, pos);
    if (idx === -1) return false;
    pos = idx + seg.length;
  }

  // Ensure middle matching didn't consume past where the last segment starts
  return pos <= value.length - last.length;
}

// ─── MCP Router ─────────────────────────────────────────────────────

/**
 * Centralized MCP tool call interception and authorization engine.
 *
 * Permissions are evaluated in order — first match wins (fail-closed).
 * If no permission matches a tool call, the call is denied by default.
 */
export class MCPRouter {
  private readonly permissions: MCPPermission[];
  private readonly stateStore?: StateStore;

  constructor(permissions: MCPPermission[], stateStore?: StateStore) {
    this.permissions = permissions;
    this.stateStore = stateStore;
  }

  /**
   * Authorize an MCP tool call against the configured permissions.
   *
   * @param call - The tool call to authorize.
   * @param context - Runtime policy context for condition evaluation.
   * @returns Authorization result (fail-closed: denied if no rule matches).
   */
  async authorize(
    call: MCPToolCall,
    context: PolicyContext,
  ): Promise<MCPAuthResult> {
    for (const perm of this.permissions) {
      if (!globMatch(perm.tool_pattern, call.tool_name)) {
        continue;
      }

      // Evaluate conditions (if any)
      if (perm.conditions && perm.conditions.length > 0) {
        const conditionsMet = this.evaluateConditions(perm.conditions, context);
        if (!conditionsMet) {
          continue; // Conditions not met — skip this permission, try next
        }
      }

      // Check session rate limit
      if (
        perm.max_calls_per_session != null &&
        perm.allowed &&
        this.stateStore
      ) {
        const key = `mcp:${call.tool_name}:${call.session_id}`;
        // Use a large window (effectively per-session, not time-windowed)
        const SESSION_WINDOW_MS = 24 * 60 * 60 * 1000; // 24 hours
        const count = await this.stateStore.recordAndCount(
          key,
          SESSION_WINDOW_MS,
        );
        if (count > perm.max_calls_per_session) {
          return {
            allowed: false,
            require_human_approval: false,
            audit_level: perm.audit_level ?? "full",
            matched_permission: perm,
            denial_reason: `Rate limit exceeded: ${count - 1} of ${perm.max_calls_per_session} allowed calls used for "${call.tool_name}" in session "${call.session_id}"`,
          };
        }
      }

      // Permission matched
      if (!perm.allowed) {
        return {
          allowed: false,
          require_human_approval: false,
          audit_level: perm.audit_level ?? "full",
          matched_permission: perm,
          denial_reason: `Tool "${call.tool_name}" denied by permission rule matching "${perm.tool_pattern}"`,
        };
      }

      return {
        allowed: true,
        require_human_approval: perm.require_human_approval ?? false,
        audit_level: perm.audit_level ?? "full",
        matched_permission: perm,
      };
    }

    // No permission matched — fail closed
    return {
      allowed: false,
      require_human_approval: false,
      audit_level: "full",
      denial_reason: `No permission rule matches tool "${call.tool_name}" — denied by default (fail-closed)`,
    };
  }

  /**
   * Evaluate an array of conditions (implicitly AND-ed).
   * Uses the synchronous evaluateConditionExpr from the evaluator.
   */
  private evaluateConditions(
    conditions: PolicyConditionExpr[],
    context: PolicyContext,
  ): boolean {
    for (const cond of conditions) {
      try {
        const result = evaluateConditionExpr(cond, context);
        if (!result.passed) return false;
      } catch {
        // If evaluation fails (e.g. rate_limit without async), treat as not met
        return false;
      }
    }
    return true;
  }
}
