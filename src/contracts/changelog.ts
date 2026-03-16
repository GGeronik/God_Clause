import { v4 as uuidv4 } from "uuid";

export type ContractChangeType = "registered" | "activated" | "deactivated" | "updated";

export interface ContractChangeEvent {
  event_id: string;
  event_type: ContractChangeType;
  contract_name: string;
  contract_version: string;
  changed_by?: string;
  timestamp: string;
  details?: string;
}

export interface ChangeLogQuery {
  contract_name?: string;
  event_type?: ContractChangeType;
  from?: string;
  to?: string;
  limit?: number;
}

/**
 * Tracks policy change history — who changed what and when.
 *
 * Answers questions like:
 * - "Who activated the new PHI policy on March 3rd?"
 * - "When was contract v2.0 registered?"
 * - "Show all deactivations in the last 30 days"
 *
 * ```ts
 * const changelog = new ContractChangeLog();
 * changelog.record({
 *   event_type: "activated",
 *   contract_name: "Healthcare AI",
 *   contract_version: "2.0.0",
 *   changed_by: "admin@example.com",
 * });
 * ```
 */
export class ContractChangeLog {
  private events: ContractChangeEvent[] = [];

  /** Record a contract change event. */
  record(event: Omit<ContractChangeEvent, "event_id" | "timestamp">): ContractChangeEvent {
    const full: ContractChangeEvent = {
      event_id: uuidv4(),
      timestamp: new Date().toISOString(),
      ...event,
    };
    this.events.push(full);
    return full;
  }

  /** Query change events with optional filters. */
  query(opts?: ChangeLogQuery): ContractChangeEvent[] {
    let results = [...this.events];

    if (opts?.contract_name) {
      results = results.filter((e) => e.contract_name === opts.contract_name);
    }
    if (opts?.event_type) {
      results = results.filter((e) => e.event_type === opts.event_type);
    }
    if (opts?.from) {
      const from = new Date(opts.from).getTime();
      results = results.filter((e) => new Date(e.timestamp).getTime() >= from);
    }
    if (opts?.to) {
      const to = new Date(opts.to).getTime();
      results = results.filter((e) => new Date(e.timestamp).getTime() <= to);
    }
    if (opts?.limit) {
      results = results.slice(-opts.limit);
    }

    return results;
  }

  /** Get all events. */
  getAll(): ReadonlyArray<ContractChangeEvent> {
    return this.events;
  }

  /** Get the most recent event for a contract. */
  getLatest(contractName: string): ContractChangeEvent | undefined {
    for (let i = this.events.length - 1; i >= 0; i--) {
      if (this.events[i].contract_name === contractName) {
        return this.events[i];
      }
    }
    return undefined;
  }
}
