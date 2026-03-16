import { createHmac } from "crypto";

export type WebhookEvent = "block" | "warn" | "modify" | "seal" | "contract_change";

export interface WebhookConfig {
  /** URL to POST event payloads to */
  url: string;
  /** Which events to send to this webhook */
  events: WebhookEvent[];
  /** Additional headers */
  headers?: Record<string, string>;
  /** HMAC-SHA256 secret for signing payloads */
  secret?: string;
}

/**
 * Webhook notifier — sends governance events to external HTTP endpoints.
 *
 * Enables integration with Slack, PagerDuty, Opsgenie, or any webhook-capable service.
 *
 * ```ts
 * const notifier = new WebhookNotifier();
 * notifier.register({
 *   url: "https://hooks.slack.com/services/...",
 *   events: ["block"],
 *   secret: "webhook-signing-secret",
 * });
 *
 * // In your GodClause hooks:
 * gov.engine.onBlock = (decision) => notifier.emit("block", { decision });
 * ```
 */
export class WebhookNotifier {
  private hooks: WebhookConfig[] = [];

  /** Register a webhook endpoint. */
  register(config: WebhookConfig): void {
    this.hooks.push(config);
  }

  /** Remove a webhook by URL. */
  unregister(url: string): void {
    this.hooks = this.hooks.filter((h) => h.url !== url);
  }

  /** Emit an event to all registered webhooks that listen for it. */
  async emit(event: WebhookEvent, payload: unknown): Promise<void> {
    const matching = this.hooks.filter((h) => h.events.includes(event));
    if (matching.length === 0) return;

    const body = JSON.stringify({
      event,
      timestamp: new Date().toISOString(),
      data: payload,
    });

    await Promise.allSettled(
      matching.map((hook) => this.send(hook, body)),
    );
  }

  private async send(hook: WebhookConfig, body: string): Promise<void> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...hook.headers,
    };

    if (hook.secret) {
      const signature = createHmac("sha256", hook.secret).update(body).digest("hex");
      headers["X-GodClause-Signature"] = `sha256=${signature}`;
    }

    try {
      await fetch(hook.url, { method: "POST", headers, body });
    } catch {
      // Silently fail — webhook delivery is best-effort
    }
  }
}
