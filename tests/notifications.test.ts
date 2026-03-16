import { describe, it, expect, vi, afterEach } from "vitest";
import { WebhookNotifier } from "../src/notifications/webhook";
import { createHmac } from "crypto";

describe("WebhookNotifier", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sends events to registered hooks", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const notifier = new WebhookNotifier();
    notifier.register({
      url: "https://hooks.example.com/webhook",
      events: ["block"],
    });

    await notifier.emit("block", { rule_id: "R-001" });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, opts] = fetchMock.mock.calls[0];
    expect(url).toBe("https://hooks.example.com/webhook");
    expect(opts.method).toBe("POST");

    const body = JSON.parse(opts.body);
    expect(body.event).toBe("block");
    expect(body.data.rule_id).toBe("R-001");
    expect(body.timestamp).toBeTruthy();
  });

  it("only sends to hooks subscribed to the event", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const notifier = new WebhookNotifier();
    notifier.register({ url: "https://a.com", events: ["block"] });
    notifier.register({ url: "https://b.com", events: ["warn"] });
    notifier.register({ url: "https://c.com", events: ["block", "warn"] });

    await notifier.emit("block", {});

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const urls = fetchMock.mock.calls.map((c: any) => c[0]);
    expect(urls).toContain("https://a.com");
    expect(urls).toContain("https://c.com");
    expect(urls).not.toContain("https://b.com");
  });

  it("does nothing for events with no subscribers", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const notifier = new WebhookNotifier();
    notifier.register({ url: "https://a.com", events: ["block"] });

    await notifier.emit("seal", {});
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("includes HMAC signature when secret is set", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const secret = "my-webhook-secret";
    const notifier = new WebhookNotifier();
    notifier.register({
      url: "https://hooks.example.com",
      events: ["block"],
      secret,
    });

    await notifier.emit("block", { test: true });

    const headers = fetchMock.mock.calls[0][1].headers;
    const body = fetchMock.mock.calls[0][1].body;
    const expectedSig = createHmac("sha256", secret).update(body).digest("hex");

    expect(headers["X-GodClause-Signature"]).toBe(`sha256=${expectedSig}`);
  });

  it("includes custom headers", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const notifier = new WebhookNotifier();
    notifier.register({
      url: "https://hooks.example.com",
      events: ["warn"],
      headers: { Authorization: "Bearer token123" },
    });

    await notifier.emit("warn", {});

    const headers = fetchMock.mock.calls[0][1].headers;
    expect(headers["Authorization"]).toBe("Bearer token123");
  });

  it("unregisters hooks by URL", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);

    const notifier = new WebhookNotifier();
    notifier.register({ url: "https://a.com", events: ["block"] });
    notifier.register({ url: "https://b.com", events: ["block"] });

    notifier.unregister("https://a.com");
    await notifier.emit("block", {});

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0][0]).toBe("https://b.com");
  });

  it("handles fetch failures gracefully", async () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("network error"));
    vi.stubGlobal("fetch", fetchMock);

    const notifier = new WebhookNotifier();
    notifier.register({ url: "https://a.com", events: ["block"] });

    // Should not throw
    await notifier.emit("block", { test: true });
    expect(fetchMock).toHaveBeenCalled();
  });
});
