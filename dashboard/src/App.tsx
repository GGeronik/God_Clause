import React, { useState, useEffect, useCallback } from "react";
import { getHealth, getContracts, getAudit, verifyAudit, getMetrics, subscribeEvents } from "./api";

type Page = "overview" | "contracts" | "audit" | "analytics";

interface Contract {
  name: string;
  version: string;
  author: string;
  description: string;
  rules_count: number;
}

interface AuditEntry {
  entry_id: string;
  decision_id: string;
  timestamp: string;
  action: string;
  allowed: boolean;
  outcome?: string;
  contract_name: string;
  caller: { user_id: string };
  blocks: string[];
  warnings: string[];
  hash: string;
}

interface LiveEvent {
  type: string;
  data: any;
  timestamp: string;
}

export default function App() {
  const [page, setPage] = useState<Page>("overview");

  return (
    <div className="min-h-screen bg-gray-950">
      <nav className="border-b border-gray-800 bg-gray-900">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-8">
          <h1 className="text-xl font-bold text-white tracking-tight">
            God Clause
          </h1>
          <div className="flex gap-1">
            {(["overview", "contracts", "audit", "analytics"] as Page[]).map((p) => (
              <button
                key={p}
                onClick={() => setPage(p)}
                className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                  page === p
                    ? "bg-blue-600 text-white"
                    : "text-gray-400 hover:text-white hover:bg-gray-800"
                }`}
              >
                {p.charAt(0).toUpperCase() + p.slice(1)}
              </button>
            ))}
          </div>
        </div>
      </nav>
      <main className="max-w-7xl mx-auto px-4 py-6">
        {page === "overview" && <OverviewPage />}
        {page === "contracts" && <ContractsPage />}
        {page === "audit" && <AuditPage />}
        {page === "analytics" && <AnalyticsPage />}
      </main>
    </div>
  );
}

// ─── Overview Page ──────────────────────────────────────────────────

function OverviewPage() {
  const [health, setHealth] = useState<{ status: string } | null>(null);
  const [contracts, setContracts] = useState<Contract[]>([]);
  const [auditCount, setAuditCount] = useState(0);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [events, setEvents] = useState<LiveEvent[]>([]);

  useEffect(() => {
    getHealth().then(setHealth).catch(() => {});
    getContracts().then((d) => setContracts(d.contracts)).catch(() => {});
    getAudit().then((d) => setAuditCount(d.total)).catch(() => {});
    verifyAudit().then((d) => setChainValid(d.valid)).catch(() => {});

    const es = subscribeEvents((type, data) => {
      setEvents((prev) => [{ type, data, timestamp: new Date().toISOString() }, ...prev].slice(0, 50));
    });
    return () => es.close();
  }, []);

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-4 gap-4">
        <StatCard
          label="Status"
          value={health?.status === "ok" ? "Healthy" : "Unknown"}
          color={health?.status === "ok" ? "green" : "gray"}
        />
        <StatCard label="Active Contracts" value={contracts.length} color="blue" />
        <StatCard label="Audit Entries" value={auditCount} color="purple" />
        <StatCard
          label="Chain Integrity"
          value={chainValid === null ? "..." : chainValid ? "Valid" : "BROKEN"}
          color={chainValid ? "green" : "red"}
        />
      </div>

      <div className="grid grid-cols-2 gap-6">
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <h2 className="text-lg font-semibold mb-3">Active Contracts</h2>
          {contracts.length === 0 ? (
            <p className="text-gray-500">No contracts loaded</p>
          ) : (
            <div className="space-y-2">
              {contracts.map((c) => (
                <div key={c.name + c.version} className="flex justify-between items-center p-2 bg-gray-800 rounded">
                  <div>
                    <span className="font-medium">{c.name}</span>
                    <span className="text-gray-500 ml-2">v{c.version}</span>
                  </div>
                  <span className="text-sm text-gray-400">{c.rules_count} rules</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
          <h2 className="text-lg font-semibold mb-3">Live Events</h2>
          {events.length === 0 ? (
            <p className="text-gray-500">Waiting for events...</p>
          ) : (
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {events.map((e, i) => (
                <div key={i} className="flex items-center gap-2 text-sm p-1">
                  <EventBadge type={e.type} />
                  <span className="text-gray-400 font-mono text-xs">
                    {new Date(e.timestamp).toLocaleTimeString()}
                  </span>
                  <span className="text-gray-300 truncate">
                    {e.type === "decision" && `${e.data.outcome} - ${e.data.action} by ${e.data.user_id}`}
                    {e.type === "violation" && `Blocked: ${e.data.blocks?.join(", ")}`}
                    {e.type === "contract_change" && `${e.data.event}: ${e.data.name}`}
                    {e.type === "seal" && `Seal: ${e.data.merkle_root?.slice(0, 16)}...`}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Contracts Page ─────────────────────────────────────────────────

function ContractsPage() {
  const [contracts, setContracts] = useState<Contract[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getContracts()
      .then((d) => setContracts(d.contracts))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-gray-500">Loading...</p>;

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Trust Contracts</h2>
      {contracts.length === 0 ? (
        <p className="text-gray-500">No contracts loaded. POST a contract to /v1/contracts to get started.</p>
      ) : (
        <div className="grid gap-4">
          {contracts.map((c) => (
            <div key={c.name + c.version} className="bg-gray-900 rounded-lg border border-gray-800 p-5">
              <div className="flex justify-between items-start">
                <div>
                  <h3 className="text-lg font-semibold">{c.name}</h3>
                  <p className="text-gray-400 text-sm mt-1">{c.description}</p>
                </div>
                <div className="text-right">
                  <span className="text-sm bg-blue-900 text-blue-300 px-2 py-0.5 rounded">v{c.version}</span>
                  <p className="text-sm text-gray-500 mt-1">by {c.author}</p>
                </div>
              </div>
              <div className="mt-3 flex gap-4 text-sm text-gray-400">
                <span>{c.rules_count} rules</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Audit Page ─────────────────────────────────────────────────────

function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [filter, setFilter] = useState({ allowed: "", action: "", user_id: "" });
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    const params: Record<string, string> = {};
    if (filter.allowed) params.allowed = filter.allowed;
    if (filter.action) params.action = filter.action;
    if (filter.user_id) params.user_id = filter.user_id;
    params.limit = "50";

    getAudit(params)
      .then((d) => {
        setEntries(d.entries);
        setTotal(d.total);
      })
      .finally(() => setLoading(false));
  }, [filter]);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-semibold">Audit Log</h2>
        <span className="text-sm text-gray-500">{total} entries</span>
      </div>

      <div className="flex gap-3">
        <select
          value={filter.allowed}
          onChange={(e) => setFilter((f) => ({ ...f, allowed: e.target.value }))}
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm"
        >
          <option value="">All decisions</option>
          <option value="true">Permitted</option>
          <option value="false">Denied</option>
        </select>
        <input
          type="text"
          placeholder="Filter by action..."
          value={filter.action}
          onChange={(e) => setFilter((f) => ({ ...f, action: e.target.value }))}
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm w-48"
        />
        <input
          type="text"
          placeholder="Filter by user_id..."
          value={filter.user_id}
          onChange={(e) => setFilter((f) => ({ ...f, user_id: e.target.value }))}
          className="bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm w-48"
        />
      </div>

      {loading ? (
        <p className="text-gray-500">Loading...</p>
      ) : entries.length === 0 ? (
        <p className="text-gray-500">No audit entries found</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-gray-500 border-b border-gray-800">
                <th className="pb-2 pr-4">Time</th>
                <th className="pb-2 pr-4">Outcome</th>
                <th className="pb-2 pr-4">Action</th>
                <th className="pb-2 pr-4">User</th>
                <th className="pb-2 pr-4">Contract</th>
                <th className="pb-2 pr-4">Blocks</th>
                <th className="pb-2 pr-4">Hash</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.entry_id} className="border-b border-gray-800/50 hover:bg-gray-900/50">
                  <td className="py-2 pr-4 font-mono text-xs text-gray-400">
                    {new Date(e.timestamp).toLocaleString()}
                  </td>
                  <td className="py-2 pr-4">
                    <OutcomeBadge outcome={e.outcome ?? (e.allowed ? "permit" : "deny")} />
                  </td>
                  <td className="py-2 pr-4">{e.action}</td>
                  <td className="py-2 pr-4 text-gray-400">{e.caller.user_id}</td>
                  <td className="py-2 pr-4 text-gray-400">{e.contract_name}</td>
                  <td className="py-2 pr-4 text-red-400">{e.blocks.join(", ") || "-"}</td>
                  <td className="py-2 pr-4 font-mono text-xs text-gray-600">{e.hash.slice(0, 12)}...</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ─── Analytics Page ─────────────────────────────────────────────────

function AnalyticsPage() {
  const [metricsText, setMetricsText] = useState("");
  const [verification, setVerification] = useState<{ valid: boolean; entries_checked: number } | null>(null);

  useEffect(() => {
    getMetrics().then(setMetricsText).catch(() => {});
    verifyAudit().then(setVerification).catch(() => {});
  }, []);

  const metrics = parsePrometheus(metricsText);

  return (
    <div className="space-y-6">
      <h2 className="text-xl font-semibold">Analytics & Metrics</h2>

      <div className="grid grid-cols-3 gap-4">
        <StatCard label="Total Decisions" value={metrics["godclause_audit_entries_total"] ?? 0} color="blue" />
        <StatCard label="Active Contracts" value={metrics["godclause_active_contracts"] ?? 0} color="purple" />
        <StatCard label="Chain Length" value={metrics["godclause_audit_chain_length"] ?? 0} color="green" />
      </div>

      {verification && (
        <div className={`p-4 rounded-lg border ${verification.valid ? "bg-green-950 border-green-800" : "bg-red-950 border-red-800"}`}>
          <h3 className="font-semibold mb-1">
            Hash Chain Verification: {verification.valid ? "VALID" : "BROKEN"}
          </h3>
          <p className="text-sm text-gray-400">{verification.entries_checked} entries checked</p>
        </div>
      )}

      <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
        <h3 className="font-semibold mb-3">Prometheus Metrics</h3>
        <pre className="text-xs text-gray-400 font-mono whitespace-pre-wrap max-h-96 overflow-y-auto">
          {metricsText || "No metrics available (server not running)"}
        </pre>
      </div>
    </div>
  );
}

// ─── Components ─────────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: string | number; color: string }) {
  const colors: Record<string, string> = {
    green: "border-green-800 bg-green-950/50",
    blue: "border-blue-800 bg-blue-950/50",
    purple: "border-purple-800 bg-purple-950/50",
    red: "border-red-800 bg-red-950/50",
    gray: "border-gray-700 bg-gray-900",
  };
  return (
    <div className={`rounded-lg border p-4 ${colors[color] || colors.gray}`}>
      <p className="text-sm text-gray-400">{label}</p>
      <p className="text-2xl font-bold mt-1">{value}</p>
    </div>
  );
}

function OutcomeBadge({ outcome }: { outcome: string }) {
  const styles: Record<string, string> = {
    permit: "bg-green-900 text-green-300",
    deny: "bg-red-900 text-red-300",
    modify: "bg-yellow-900 text-yellow-300",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${styles[outcome] || "bg-gray-800 text-gray-400"}`}>
      {outcome}
    </span>
  );
}

function EventBadge({ type }: { type: string }) {
  const styles: Record<string, string> = {
    decision: "bg-blue-900 text-blue-300",
    violation: "bg-red-900 text-red-300",
    contract_change: "bg-purple-900 text-purple-300",
    seal: "bg-green-900 text-green-300",
  };
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${styles[type] || "bg-gray-800 text-gray-400"}`}>
      {type}
    </span>
  );
}

function parsePrometheus(text: string): Record<string, string> {
  const metrics: Record<string, string> = {};
  for (const line of text.split("\n")) {
    if (line.startsWith("#") || !line.trim()) continue;
    const match = line.match(/^(\w+)(?:\{[^}]*\})?\s+(.+)$/);
    if (match) metrics[match[1]] = match[2];
  }
  return metrics;
}
