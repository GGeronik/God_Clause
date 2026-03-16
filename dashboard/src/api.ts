const BASE = "/v1";

async function fetchJSON<T>(path: string, opts?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, opts);
  return res.json();
}

export async function getHealth() {
  return fetchJSON<{ status: string; timestamp: string }>("/health");
}

export async function getReady() {
  return fetchJSON<{ ready: boolean; contracts_loaded: number }>("/ready");
}

export async function getContracts() {
  return fetchJSON<{
    contracts: Array<{
      name: string;
      version: string;
      author: string;
      description: string;
      rules_count: number;
    }>;
  }>("/contracts");
}

export async function getAudit(params?: Record<string, string>) {
  const qs = params ? "?" + new URLSearchParams(params).toString() : "";
  return fetchJSON<{
    entries: Array<{
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
    }>;
    total: number;
  }>(`/audit${qs}`);
}

export async function verifyAudit() {
  return fetchJSON<{ valid: boolean; brokenAt?: number; entries_checked: number }>(
    "/audit/verify",
  );
}

export async function getMetrics(): Promise<string> {
  const res = await fetch(`${BASE}/metrics`);
  return res.text();
}

export function subscribeEvents(onEvent: (event: string, data: any) => void): EventSource {
  const es = new EventSource(`${BASE}/events`);
  es.addEventListener("decision", (e) => onEvent("decision", JSON.parse(e.data)));
  es.addEventListener("violation", (e) => onEvent("violation", JSON.parse(e.data)));
  es.addEventListener("contract_change", (e) => onEvent("contract_change", JSON.parse(e.data)));
  es.addEventListener("seal", (e) => onEvent("seal", JSON.parse(e.data)));
  return es;
}
