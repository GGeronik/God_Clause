import type { AuditEntry } from "../types";

/**
 * Export audit entries as CSV string.
 */
export function exportAuditCSV(entries: AuditEntry[]): string {
  const headers = [
    "entry_id", "decision_id", "timestamp", "action", "allowed",
    "outcome", "contract_name", "contract_version", "user_id",
    "blocks", "warnings", "obligations", "tenant_id", "trace_id",
    "policy_sha256", "hash",
  ];

  const rows = entries.map((e) =>
    [
      e.entry_id,
      e.decision_id,
      e.timestamp,
      e.action,
      e.allowed,
      e.outcome ?? "",
      e.contract_name,
      e.contract_version,
      e.caller.user_id,
      e.blocks.join(";"),
      e.warnings.join(";"),
      (e.obligations ?? []).join(";"),
      e.tenant_id ?? "",
      e.trace_id ?? "",
      e.policy_sha256 ?? "",
      e.hash,
    ]
      .map((v) => `"${String(v).replace(/"/g, '""')}"`)
      .join(","),
  );

  return [headers.join(","), ...rows].join("\n");
}

/**
 * Export audit entries as formatted JSON string.
 */
export function exportAuditJSON(
  entries: AuditEntry[],
  opts?: { pretty?: boolean },
): string {
  return JSON.stringify(entries, null, opts?.pretty ? 2 : undefined);
}

/**
 * Generate an analytics summary of audit entries.
 */
export function exportAuditSummary(entries: AuditEntry[]): AuditSummary {
  const permits = entries.filter((e) => e.allowed && (!e.outcome || e.outcome === "permit")).length;
  const denies = entries.filter((e) => !e.allowed || e.outcome === "deny").length;
  const modifies = entries.filter((e) => e.outcome === "modify").length;

  // Top blocked rules
  const ruleBlockCounts = new Map<string, number>();
  for (const e of entries) {
    for (const ruleId of e.blocks) {
      ruleBlockCounts.set(ruleId, (ruleBlockCounts.get(ruleId) ?? 0) + 1);
    }
  }
  const topBlockedRules = [...ruleBlockCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([rule_id, count]) => ({ rule_id, count }));

  // Top users by decision count
  const userCounts = new Map<string, number>();
  for (const e of entries) {
    const uid = e.caller.user_id;
    userCounts.set(uid, (userCounts.get(uid) ?? 0) + 1);
  }
  const topUsers = [...userCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([user_id, count]) => ({ user_id, count }));

  // Timeline (by hour)
  const hourCounts = new Map<string, number>();
  for (const e of entries) {
    const hour = e.timestamp.slice(0, 13); // "2026-03-15T14"
    hourCounts.set(hour, (hourCounts.get(hour) ?? 0) + 1);
  }
  const timeline = [...hourCounts.entries()]
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([hour, count]) => ({ hour, count }));

  // Top actions
  const actionCounts = new Map<string, number>();
  for (const e of entries) {
    actionCounts.set(e.action, (actionCounts.get(e.action) ?? 0) + 1);
  }
  const topActions = [...actionCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([action, count]) => ({ action, count }));

  // Contracts
  const contractCounts = new Map<string, number>();
  for (const e of entries) {
    const key = `${e.contract_name} v${e.contract_version}`;
    contractCounts.set(key, (contractCounts.get(key) ?? 0) + 1);
  }
  const contractBreakdown = [...contractCounts.entries()]
    .map(([contract, count]) => ({ contract, count }));

  return {
    total_decisions: entries.length,
    permits,
    denies,
    modifies,
    denial_rate: entries.length > 0 ? denies / entries.length : 0,
    top_blocked_rules: topBlockedRules,
    top_users: topUsers,
    top_actions: topActions,
    contract_breakdown: contractBreakdown,
    timeline,
    date_range: entries.length > 0
      ? { from: entries[0].timestamp, to: entries[entries.length - 1].timestamp }
      : undefined,
  };
}

export interface AuditSummary {
  total_decisions: number;
  permits: number;
  denies: number;
  modifies: number;
  denial_rate: number;
  top_blocked_rules: Array<{ rule_id: string; count: number }>;
  top_users: Array<{ user_id: string; count: number }>;
  top_actions: Array<{ action: string; count: number }>;
  contract_breakdown: Array<{ contract: string; count: number }>;
  timeline: Array<{ hour: string; count: number }>;
  date_range?: { from: string; to: string };
}
