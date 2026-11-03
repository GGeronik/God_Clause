import { createServer as createHttpServer, IncomingMessage, ServerResponse } from "http";
import { timingSafeEqual } from "crypto";
import { readFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";
import { GodClause, GovernanceOptions } from "../governance";
import { MemoryStateStore } from "../engine/state-store";
import { FileAuditSink } from "../audit/file-sink";
import type { PolicyContext, EvaluateOptions, AuditQuery, PolicyDecision } from "../types";

export interface ServerOptions {
  port?: number;
  contractsDir?: string;
  auditDir?: string;
  hmacSecret?: string;
  /** Bearer token every request except /v1/health and /v1/ready must carry. Unset = unauthenticated (logged as a warning). */
  apiToken?: string;
  /** Largest accepted request body in bytes. Default 1 MiB. */
  maxBodyBytes?: number;
  logLevel?: "debug" | "info" | "warn" | "error";
}

/** An error the request handler turns into an HTTP status instead of a 500. */
function httpError(status: number, error: string, message: string): Error & { status: number; error: string } {
  return Object.assign(new Error(message), { status, error });
}

export interface GodClauseServer {
  start(): Promise<void>;
  stop(): Promise<void>;
  gov: GodClause;
}

/**
 * Create a standalone God Clause HTTP server (Policy Decision Point).
 *
 * ```ts
 * const server = createServer({ port: 3000, contractsDir: "./contracts" });
 * await server.start();
 * ```
 */
export function createServer(opts: ServerOptions = {}): GodClauseServer {
  const port = opts.port ?? parseInt(process.env.PORT ?? "3000", 10);
  const contractsDir = opts.contractsDir ?? process.env.CONTRACTS_DIR ?? "./contracts";
  const auditDir = opts.auditDir ?? process.env.AUDIT_DIR;
  // A blank or whitespace-only env var (`${VAR:-}` in compose files) means unset; absences are logged at start.
  const rawSecret = opts.hmacSecret ?? process.env.AUDIT_HMAC_SECRET;
  const hmacSecret = rawSecret?.trim() ? rawSecret : undefined;
  const apiToken = (opts.apiToken ?? process.env.API_TOKEN)?.trim() || undefined;
  const capSetting = opts.maxBodyBytes ?? Number(process.env.MAX_BODY_BYTES || NaN);
  const maxBodyBytes = Number.isSafeInteger(capSetting) && capSetting > 0 ? capSetting : 1024 * 1024;
  const logLevel = opts.logLevel ?? (process.env.LOG_LEVEL as any) ?? "info";

  const stateStore = new MemoryStateStore();
  const govOpts: GovernanceOptions = {
    stateStore,
    auditSecretKey: hmacSecret,
  };

  if (auditDir) {
    const auditPath = join(auditDir, "audit.jsonl");
    govOpts.auditSinks = [new FileAuditSink({ path: auditPath })];
    govOpts.auditHeadHash = FileAuditSink.lastHash(auditPath);
  }

  const gov = new GodClause(govOpts);

  // SSE clients
  const sseClients = new Set<ServerResponse>();

  // Metrics state
  const metrics = {
    decisions_total: new Map<string, number>(),
    blocks_total: new Map<string, number>(),
    evaluation_durations: [] as number[],
    audit_entries_total: 0,
  };
  function count(decision: PolicyDecision, startedAt: number): number {
    metrics.decisions_total.set(decision.outcome, (metrics.decisions_total.get(decision.outcome) ?? 0) + 1);
    for (const b of decision.blocks)
      metrics.blocks_total.set(b.rule_id, (metrics.blocks_total.get(b.rule_id) ?? 0) + 1);
    if (metrics.evaluation_durations.length >= 10_000) metrics.evaluation_durations.shift();
    const ms = Date.now() - startedAt;
    metrics.evaluation_durations.push(ms);
    metrics.audit_entries_total++;
    return ms;
  }
  const promLabel = (v: string) => v.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");

  // Load contracts from directory
  function loadContracts(): void {
    if (!existsSync(contractsDir)) return;
    const files = readdirSync(contractsDir).filter(
      (f) => f.endsWith(".yaml") || f.endsWith(".yml") || f.endsWith(".json"),
    );
    for (const file of files) {
      try {
        const source = readFileSync(join(contractsDir, file), "utf-8");
        gov.loadContractYAML(source);
        log("info", `Loaded contract: ${file}`);
      } catch (err: any) {
        log("error", `Failed to load ${file}: ${err.message}`);
      }
    }
  }

  function log(level: string, msg: string): void {
    const levels = ["debug", "info", "warn", "error"];
    if (levels.indexOf(level) < levels.indexOf(logLevel)) return;
    const entry = JSON.stringify({
      level,
      msg,
      ts: new Date().toISOString(),
      service: "god-clause",
    });
    if (level === "error") console.error(entry);
    else console.log(entry);
  }

  function sendSSE(event: string, data: unknown): void {
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const client of sseClients) {
      try {
        client.write(payload);
      } catch {
        sseClients.delete(client);
      }
    }
  }

  function parseBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let size = 0;
      req.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxBodyBytes) {
          req.removeAllListeners("data");
          req.removeAllListeners("end");
          reject(httpError(413, "payload_too_large", `Request body exceeds ${maxBodyBytes} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => resolve(Buffer.concat(chunks).toString()));
      req.on("error", reject);
    });
  }

  async function readJson(req: IncomingMessage): Promise<any> {
    const text = await parseBody(req);
    try {
      return JSON.parse(text);
    } catch {
      throw httpError(400, "invalid_json", "Request body is not valid JSON");
    }
  }

  function contextFrom(body: any): PolicyContext {
    if (!body || typeof body !== "object" || typeof body.action !== "string" || body.action === "") {
      throw httpError(400, "invalid_request", "action must be a non-empty string");
    }
    const c = body.caller;
    if (
      !c ||
      typeof c !== "object" ||
      typeof c.user_id !== "string" ||
      typeof c.session_id !== "string" ||
      !Array.isArray(c.roles)
    ) {
      throw httpError(400, "invalid_request", "caller must have user_id, session_id and roles[]");
    }
    return {
      action: body.action,
      input: body.input ?? {},
      output: body.output,
      caller: c,
      metadata: body.metadata,
      trace: body.trace,
    };
  }

  function optionsFrom(body: any): EvaluateOptions {
    const given = body.options ?? {};
    const evalOpts: EvaluateOptions = {};
    for (const key of ["includeTags", "excludeTags"] as const) {
      if (given[key] === undefined) continue;
      if (!Array.isArray(given[key]) || !given[key].every((t: unknown) => typeof t === "string")) {
        throw httpError(400, "invalid_request", `options.${key} must be an array of strings`);
      }
      evalOpts[key] = given[key];
    }
    return evalOpts;
  }

  function authorized(req: IncomingMessage): boolean {
    if (!apiToken) return true;
    const match = /^bearer (.*)$/i.exec(req.headers.authorization ?? "");
    // Node decodes header bytes as latin1; re-encode so a UTF-8 token sent on the wire compares byte for byte.
    const given = Buffer.from(match ? match[1] : "", "latin1");
    const expected = Buffer.from(apiToken);
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  function noContracts(res: ServerResponse): boolean {
    if (gov.getContracts().length > 0) return false;
    json(res, 503, { error: "no_contracts", message: "No trust contract is loaded; refusing to decide" });
    return true;
  }

  function json(res: ServerResponse, status: number, data: unknown): void {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
  }

  function matchRoute(
    method: string,
    url: string,
    targetMethod: string,
    pattern: string,
  ): Record<string, string> | null {
    if (method !== targetMethod) return null;
    const patternParts = pattern.split("/");
    const urlParts = url.split("?")[0].split("/");
    if (patternParts.length !== urlParts.length) return null;
    const params: Record<string, string> = {};
    for (let i = 0; i < patternParts.length; i++) {
      if (patternParts[i].startsWith(":")) {
        try {
          params[patternParts[i].slice(1)] = decodeURIComponent(urlParts[i]);
        } catch {
          throw httpError(400, "invalid_request", "Malformed URL encoding");
        }
      } else if (patternParts[i] !== urlParts[i]) {
        return null;
      }
    }
    return params;
  }

  function parseQueryParams(url: string): Record<string, string> {
    return Object.fromEntries(new URL(url, "http://localhost").searchParams);
  }

  const httpServer = createHttpServer(async (req, res) => {
    const method = req.method ?? "GET";
    const url = req.url ?? "/";

    // CORS
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    const probe = matchRoute(method, url, "GET", "/v1/health") || matchRoute(method, url, "GET", "/v1/ready");
    if (!probe && !authorized(req)) {
      res.setHeader("WWW-Authenticate", "Bearer");
      json(res, 401, { error: "unauthorized", message: "A valid bearer token is required" });
      return;
    }

    try {
      // ─── Health ─────────────────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/health")) {
        json(res, 200, { status: "ok", timestamp: new Date().toISOString() });
        return;
      }

      // ─── Ready ──────────────────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/ready")) {
        const contracts = gov.getContracts();
        const ready = contracts.length > 0;
        json(res, ready ? 200 : 503, {
          ready,
          contracts_loaded: contracts.length,
          timestamp: new Date().toISOString(),
        });
        return;
      }

      // ─── Evaluate ───────────────────────────────────────
      if (matchRoute(method, url, "POST", "/v1/evaluate")) {
        if (noContracts(res)) return;
        const body = await readJson(req);
        const ctx = contextFrom(body);
        const evalOpts = optionsFrom(body);

        const start = Date.now();
        const decision = await gov.evaluate(ctx, evalOpts);
        const duration = count(decision, start);

        // SSE
        sendSSE("decision", {
          decision_id: decision.decision_id,
          outcome: decision.outcome,
          action: ctx.action,
          user_id: ctx.caller.user_id,
          timestamp: decision.timestamp,
        });
        if (decision.outcome === "deny") {
          sendSSE("violation", {
            decision_id: decision.decision_id,
            blocks: decision.blocks.map((b) => b.rule_id),
            user_id: ctx.caller.user_id,
          });
        }

        json(res, 200, {
          decision_id: decision.decision_id,
          outcome: decision.outcome,
          allowed: decision.allowed,
          obligations: decision.obligations,
          warnings: decision.warnings.map((w) => ({
            rule_id: w.rule_id,
            description: w.rule_description,
          })),
          blocks: decision.blocks.map((b) => ({
            rule_id: b.rule_id,
            description: b.rule_description,
          })),
          modifications: decision.modifications.map((m) => ({
            rule_id: m.rule_id,
            description: m.rule_description,
          })),
          governance_context: decision.governance_context,
          evaluation_ms: duration,
        });
        return;
      }

      // ─── Enforce ────────────────────────────────────────
      if (matchRoute(method, url, "POST", "/v1/enforce")) {
        if (noContracts(res)) return;
        const body = await readJson(req);
        const ctx = contextFrom(body);
        const evalOpts = optionsFrom(body);

        const start = Date.now();
        try {
          const decision = await gov.enforce(ctx, evalOpts);
          count(decision, start);
          json(res, 200, {
            decision_id: decision.decision_id,
            outcome: decision.outcome,
            allowed: decision.allowed,
            obligations: decision.obligations,
            governance_context: decision.governance_context,
          });
        } catch (err: any) {
          if (err.name === "PolicyViolationError") {
            if (err.decision) count(err.decision, start);
            json(res, 403, {
              error: "policy_violation",
              message: err.message,
              decision: err.decision
                ? {
                    decision_id: err.decision.decision_id,
                    outcome: err.decision.outcome,
                    blocks: err.decision.blocks.map((b: any) => ({
                      rule_id: b.rule_id,
                      description: b.rule_description,
                    })),
                  }
                : undefined,
            });
          } else {
            throw err;
          }
        }
        return;
      }

      // ─── List Contracts ─────────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/contracts")) {
        const contracts = gov.getContracts().map((c) => ({
          name: c.metadata.name,
          version: c.metadata.version,
          author: c.metadata.author,
          description: c.metadata.description,
          effective_date: c.metadata.effective_date,
          rules_count: c.rules.length,
        }));
        json(res, 200, { contracts });
        return;
      }

      // ─── Load Contract ──────────────────────────────────
      if (matchRoute(method, url, "POST", "/v1/contracts")) {
        const body = await parseBody(req);
        try {
          const contract = gov.loadContractYAML(body);
          sendSSE("contract_change", {
            event: "loaded",
            name: contract.metadata.name,
            version: contract.metadata.version,
          });
          json(res, 201, {
            name: contract.metadata.name,
            version: contract.metadata.version,
            rules_count: contract.rules.length,
          });
        } catch (err: any) {
          json(res, 400, { error: "invalid_contract", message: err.message, details: err.errors });
        }
        return;
      }

      // ─── Activate Contract ──────────────────────────────
      let params = matchRoute(method, url, "PUT", "/v1/contracts/:name/activate/:version");
      if (params) {
        try {
          gov.activateContract(params.name, params.version);
          sendSSE("contract_change", { event: "activated", name: params.name, version: params.version });
          json(res, 200, { activated: true, name: params.name, version: params.version });
        } catch (err: any) {
          json(res, 404, { error: "not_found", message: err.message });
        }
        return;
      }

      // ─── Deactivate Contract ────────────────────────────
      params = matchRoute(method, url, "PUT", "/v1/contracts/:name/deactivate/:version");
      if (params) {
        try {
          gov.deactivateContract(params.name, params.version);
          sendSSE("contract_change", { event: "deactivated", name: params.name, version: params.version });
          json(res, 200, { deactivated: true, name: params.name, version: params.version });
        } catch (err: any) {
          json(res, 404, { error: "not_found", message: err.message });
        }
        return;
      }

      // ─── Query Audit ────────────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/audit")) {
        const qp = parseQueryParams(url);
        const query: AuditQuery = {};
        for (const key of ["from", "to"] as const) {
          if (!qp[key]) continue;
          if (Number.isNaN(Date.parse(qp[key]))) throw httpError(400, "invalid_request", `${key} must be a date`);
          query[key] = qp[key];
        }
        if (qp.action) query.action = qp.action;
        if (qp.user_id) query.user_id = qp.user_id;
        if (qp.allowed === "true" || qp.allowed === "false") query.allowed = qp.allowed === "true";
        if (qp.rule_id) query.rule_id = qp.rule_id;
        if (qp.tenant_id) query.tenant_id = qp.tenant_id;
        if (qp.trace_id) query.trace_id = qp.trace_id;
        const limit = Number(qp.limit);
        if (Number.isInteger(limit) && limit > 0) query.limit = limit;
        const offset = Number(qp.offset);
        if (Number.isInteger(offset) && offset > 0) query.offset = offset;

        const entries = gov.queryAudit(query);
        json(res, 200, { entries, total: entries.length });
        return;
      }

      // ─── Verify Audit Chain ─────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/audit/verify")) {
        const result = gov.verifyAuditChain(hmacSecret);
        json(res, 200, {
          ...result,
          entries_checked: gov.getAuditEntries().length,
        });
        return;
      }

      // ─── Seal Audit Chain ──────────────────────────────
      if (matchRoute(method, url, "POST", "/v1/audit/seal")) {
        try {
          const seal = gov.sealAuditChain();
          sendSSE("seal", { seal_id: seal.seal_id, merkle_root: seal.merkle_root });
          json(res, 201, seal);
        } catch (err: any) {
          json(res, 400, { error: "seal_failed", message: err.message });
        }
        return;
      }

      // ─── Metrics (Prometheus) ───────────────────────────
      if (matchRoute(method, url, "GET", "/v1/metrics")) {
        const lines: string[] = [];

        lines.push("# HELP godclause_decisions_total Total policy decisions by outcome");
        lines.push("# TYPE godclause_decisions_total counter");
        for (const [outcome, n] of metrics.decisions_total) {
          lines.push(`godclause_decisions_total{outcome="${promLabel(outcome)}"} ${n}`);
        }

        lines.push("# HELP godclause_blocks_total Total blocked decisions by rule");
        lines.push("# TYPE godclause_blocks_total counter");
        for (const [ruleId, n] of metrics.blocks_total) {
          lines.push(`godclause_blocks_total{rule_id="${promLabel(ruleId)}"} ${n}`);
        }

        lines.push("# HELP godclause_audit_entries_total Total audit entries recorded");
        lines.push("# TYPE godclause_audit_entries_total counter");
        lines.push(`godclause_audit_entries_total ${metrics.audit_entries_total}`);

        lines.push("# HELP godclause_active_contracts Number of active contracts");
        lines.push("# TYPE godclause_active_contracts gauge");
        lines.push(`godclause_active_contracts ${gov.getContracts().length}`);

        lines.push("# HELP godclause_audit_chain_length Length of audit hash chain");
        lines.push("# TYPE godclause_audit_chain_length gauge");
        lines.push(`godclause_audit_chain_length ${gov.getAuditEntries().length}`);

        if (metrics.evaluation_durations.length > 0) {
          const sorted = [...metrics.evaluation_durations].sort((a, b) => a - b);
          const p50 = sorted[Math.floor(sorted.length * 0.5)] / 1000;
          const p95 = sorted[Math.floor(sorted.length * 0.95)] / 1000;
          const p99 = sorted[Math.floor(sorted.length * 0.99)] / 1000;
          const sum = sorted.reduce((a, b) => a + b, 0) / 1000;

          lines.push(
            "# HELP godclause_evaluation_duration_seconds Policy evaluation duration over the last 10000 decisions",
          );
          lines.push("# TYPE godclause_evaluation_duration_seconds summary");
          lines.push(`godclause_evaluation_duration_seconds{quantile="0.5"} ${p50}`);
          lines.push(`godclause_evaluation_duration_seconds{quantile="0.95"} ${p95}`);
          lines.push(`godclause_evaluation_duration_seconds{quantile="0.99"} ${p99}`);
          lines.push(`godclause_evaluation_duration_seconds_sum ${sum}`);
          lines.push(`godclause_evaluation_duration_seconds_count ${sorted.length}`);
        }

        res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" });
        res.end(lines.join("\n") + "\n");
        return;
      }

      // ─── SSE Events ────────────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/events")) {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
          "Access-Control-Allow-Origin": "*",
        });
        res.write("event: connected\ndata: {}\n\n");
        sseClients.add(res);
        req.on("close", () => sseClients.delete(res));
        return;
      }

      // ─── Batch Evaluate ─────────────────────────────────
      if (matchRoute(method, url, "POST", "/v1/evaluate/batch")) {
        if (noContracts(res)) return;
        const body = await readJson(req);
        if (!body || !Array.isArray(body.contexts)) {
          throw httpError(400, "invalid_request", "body.contexts must be an array");
        }
        const contexts = body.contexts.map(contextFrom);

        const results = [];
        for (const ctx of contexts) {
          const start = Date.now();
          const decision = await gov.evaluate(ctx, optionsFrom(body));
          count(decision, start);
          results.push({
            decision_id: decision.decision_id,
            outcome: decision.outcome,
            allowed: decision.allowed,
            blocks: decision.blocks.map((b: any) => b.rule_id),
            warnings: decision.warnings.map((w: any) => w.rule_id),
            obligations: decision.obligations,
          });
        }

        json(res, 200, { results });
        return;
      }

      // ─── MCP Authorize ──────────────────────────────────
      if (matchRoute(method, url, "POST", "/v1/mcp/authorize")) {
        if (noContracts(res)) return;
        const body = await readJson(req);
        if (!body || typeof body.tool_name !== "string") {
          throw httpError(400, "invalid_request", "tool_name must be a string");
        }
        if (body.session_id !== undefined && typeof body.session_id !== "string") {
          throw httpError(400, "invalid_request", "session_id must be a string");
        }
        const caller = body.caller ?? { user_id: "unknown", session_id: body.session_id ?? "unknown", roles: [] };
        if (body.session_id !== undefined && caller && typeof caller === "object") caller.session_id = body.session_id;
        const metadata = body.metadata && typeof body.metadata === "object" ? body.metadata : {};

        // Evaluated like any decision, so the contracts' mcp_permissions apply and the call is audited.
        const start = Date.now();
        const decision = await gov.evaluate(
          contextFrom({
            action: "mcp_call",
            input: body.arguments ?? {},
            caller,
            metadata: { ...metadata, mcp_tool: body.tool_name },
          }),
        );
        count(decision, start);
        json(res, decision.allowed ? 200 : 403, {
          allowed: decision.allowed,
          require_human_approval: decision.obligations.some((o) => o.obligation_id === "OBL-MCP-HUMAN-APPROVAL"),
          denial_reason: decision.allowed ? undefined : decision.blocks.map((b) => b.rule_description).join("; "),
          decision_id: decision.decision_id,
          obligations: decision.obligations,
          governance_context: decision.governance_context,
        });
        return;
      }

      // ─── Proof Bundle Export ──────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/proof-bundle")) {
        const { ProofBundleBuilder } = await import("../audit/proof-bundle");
        const qp = parseQueryParams(url);
        const builder = new ProofBundleBuilder(gov);
        const bundle = await builder.build({ from: qp.from, to: qp.to });
        json(res, 200, bundle);
        return;
      }

      // ─── Proof Bundle Verify ──────────────────────────────
      if (matchRoute(method, url, "POST", "/v1/proof-bundle/verify")) {
        const { ProofBundleBuilder } = await import("../audit/proof-bundle");
        const body = await readJson(req);
        const isRecord = (x: unknown): boolean => !!x && typeof x === "object";
        if (
          !body ||
          !Array.isArray(body.audit_entries) ||
          !body.audit_entries.every(isRecord) ||
          !Array.isArray(body.merkle_seals) ||
          !body.merkle_seals.every(isRecord)
        ) {
          throw httpError(400, "invalid_request", "body must be a proof bundle");
        }
        const builder = new ProofBundleBuilder(gov);
        const result = await builder.verify(body, hmacSecret);
        json(res, result.valid ? 200 : 400, result);
        return;
      }

      // ─── 404 ────────────────────────────────────────────
      json(res, 404, { error: "not_found", message: `${method} ${url} not found` });
    } catch (err: any) {
      if (typeof err?.status === "number") {
        json(res, err.status, { error: err.error, message: err.message });
        return;
      }
      log("error", `Request error: ${err?.message ?? err}`);
      json(res, 500, { error: "internal_error", message: "Internal error; see server log" });
    }
  });

  // Bound how long a client may take to send a request; stalled uploads otherwise hold their buffers for 5 minutes.
  httpServer.headersTimeout = 10_000;
  httpServer.requestTimeout = 30_000;

  // Load contracts on init
  loadContracts();

  return {
    gov,
    start: () =>
      new Promise<void>((resolve) => {
        httpServer.listen(port, () => {
          log("info", `God Clause server listening on port ${port}`);
          if (!apiToken) log("warn", "API_TOKEN is not set: every endpoint accepts unauthenticated requests");
          if (!hmacSecret) log("warn", "AUDIT_HMAC_SECRET is not set: audit entries are hash-chained but not signed");
          if (!auditDir) log("warn", "AUDIT_DIR is not set: audit entries are kept in memory only and lost on exit");
          if (capSetting !== maxBodyBytes && !Number.isNaN(capSetting)) {
            log("warn", `MAX_BODY_BYTES ${capSetting} is not a positive integer; using ${maxBodyBytes}`);
          }
          log("info", `Contracts loaded: ${gov.getContracts().length}`);
          log("info", `Endpoints: POST /v1/evaluate, GET /v1/health, GET /v1/metrics`);
          resolve();
        });
      }),
    stop: () =>
      new Promise<void>((resolve, reject) => {
        for (const client of sseClients) {
          client.end();
        }
        sseClients.clear();
        httpServer.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
