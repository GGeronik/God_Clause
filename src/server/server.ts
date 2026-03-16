import { createServer as createHttpServer, IncomingMessage, ServerResponse } from "http";
import { readFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";
import { GodClause, GovernanceOptions } from "../governance";
import { MemoryStateStore } from "../engine/state-store";
import { FileAuditSink } from "../audit/file-sink";
import type { PolicyContext, EvaluateOptions, AuditQuery } from "../types";

export interface ServerOptions {
  port?: number;
  contractsDir?: string;
  auditDir?: string;
  hmacSecret?: string;
  watchContracts?: boolean;
  logLevel?: "debug" | "info" | "warn" | "error";
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
  const hmacSecret = opts.hmacSecret ?? process.env.AUDIT_HMAC_SECRET;
  const logLevel = opts.logLevel ?? (process.env.LOG_LEVEL as any) ?? "info";

  const govOpts: GovernanceOptions = {
    stateStore: new MemoryStateStore(),
    auditSecretKey: hmacSecret,
  };

  if (auditDir) {
    const { MemoryAuditSink: MemSink } = require("../audit/audit-log");
    govOpts.auditSinks = [new MemSink(), new FileAuditSink({ path: join(auditDir, "audit.jsonl") })];
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
      req.on("data", (chunk) => chunks.push(chunk));
      req.on("end", () => resolve(Buffer.concat(chunks).toString()));
      req.on("error", reject);
    });
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
        params[patternParts[i].slice(1)] = decodeURIComponent(urlParts[i]);
      } else if (patternParts[i] !== urlParts[i]) {
        return null;
      }
    }
    return params;
  }

  function parseQueryParams(url: string): Record<string, string> {
    const idx = url.indexOf("?");
    if (idx === -1) return {};
    const params: Record<string, string> = {};
    const search = url.slice(idx + 1);
    for (const pair of search.split("&")) {
      const [k, v] = pair.split("=");
      if (k) params[decodeURIComponent(k)] = decodeURIComponent(v ?? "");
    }
    return params;
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
        const body = JSON.parse(await parseBody(req));
        const ctx: PolicyContext = {
          action: body.action,
          input: body.input ?? {},
          output: body.output,
          caller: body.caller,
          metadata: body.metadata,
          trace: body.trace,
        };
        const evalOpts: EvaluateOptions = {};
        if (body.options?.includeTags) evalOpts.includeTags = body.options.includeTags;
        if (body.options?.excludeTags) evalOpts.excludeTags = body.options.excludeTags;

        const start = Date.now();
        const decision = await gov.evaluate(ctx, evalOpts);
        const duration = Date.now() - start;

        // Metrics
        const key = `outcome=${decision.outcome}`;
        metrics.decisions_total.set(key, (metrics.decisions_total.get(key) ?? 0) + 1);
        metrics.evaluation_durations.push(duration);
        metrics.audit_entries_total++;

        if (decision.blocks.length > 0) {
          for (const b of decision.blocks) {
            const bKey = `rule_id=${b.rule_id}`;
            metrics.blocks_total.set(bKey, (metrics.blocks_total.get(bKey) ?? 0) + 1);
          }
        }

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
        const body = JSON.parse(await parseBody(req));
        const ctx: PolicyContext = {
          action: body.action,
          input: body.input ?? {},
          output: body.output,
          caller: body.caller,
          metadata: body.metadata,
          trace: body.trace,
        };
        const evalOpts: EvaluateOptions = {};
        if (body.options?.includeTags) evalOpts.includeTags = body.options.includeTags;
        if (body.options?.excludeTags) evalOpts.excludeTags = body.options.excludeTags;

        try {
          const decision = await gov.enforce(ctx, evalOpts);
          json(res, 200, {
            decision_id: decision.decision_id,
            outcome: decision.outcome,
            allowed: decision.allowed,
            obligations: decision.obligations,
            governance_context: decision.governance_context,
          });
        } catch (err: any) {
          if (err.name === "PolicyViolationError") {
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
        if (qp.from) query.from = qp.from;
        if (qp.to) query.to = qp.to;
        if (qp.action) query.action = qp.action;
        if (qp.user_id) query.user_id = qp.user_id;
        if (qp.allowed) query.allowed = qp.allowed === "true";
        if (qp.rule_id) query.rule_id = qp.rule_id;
        if (qp.tenant_id) query.tenant_id = qp.tenant_id;
        if (qp.trace_id) query.trace_id = qp.trace_id;
        if (qp.limit) query.limit = parseInt(qp.limit, 10);
        if (qp.offset) query.offset = parseInt(qp.offset, 10);

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
        for (const [labels, count] of metrics.decisions_total) {
          lines.push(`godclause_decisions_total{${labels}} ${count}`);
        }

        lines.push("# HELP godclause_blocks_total Total blocked decisions by rule");
        lines.push("# TYPE godclause_blocks_total counter");
        for (const [labels, count] of metrics.blocks_total) {
          lines.push(`godclause_blocks_total{${labels}} ${count}`);
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

          lines.push("# HELP godclause_evaluation_duration_seconds Policy evaluation duration");
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
        const body = JSON.parse(await parseBody(req));
        if (!Array.isArray(body.contexts)) {
          json(res, 400, { error: "invalid_request", message: "body.contexts must be an array" });
          return;
        }

        const results = [];
        for (const item of body.contexts) {
          const ctx: PolicyContext = {
            action: item.action,
            input: item.input ?? {},
            output: item.output,
            caller: item.caller,
            metadata: item.metadata,
            trace: item.trace,
          };
          const decision = await gov.evaluate(ctx, body.options);
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
        const { MCPRouter } = await import("../engine/mcp-router");
        const body = JSON.parse(await parseBody(req));

        // Collect MCP permissions from all active contracts
        const permissions = gov.getContracts().flatMap((c) => c.mcp_permissions ?? []);
        const router = new MCPRouter(permissions);

        const result = await router.authorize(
          { tool_name: body.tool_name, arguments: body.arguments ?? {}, session_id: body.session_id ?? "unknown" },
          {
            action: "mcp_call",
            input: body.arguments ?? {},
            caller: body.caller ?? { user_id: "unknown", session_id: body.session_id ?? "unknown", roles: [] },
          },
        );

        json(res, result.allowed ? 200 : 403, result);
        return;
      }

      // ─── Human Override ───────────────────────────────────
      if (matchRoute(method, url, "POST", "/v1/override")) {
        const { HumanOverrideManager } = await import("../engine/human-override");
        const body = JSON.parse(await parseBody(req));
        const manager = new HumanOverrideManager();

        try {
          const override = await manager.recordOverride(body);
          json(res, 201, override);
        } catch (err: any) {
          json(res, 400, { error: "invalid_override", message: err.message });
        }
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
        const body = JSON.parse(await parseBody(req));
        const builder = new ProofBundleBuilder(gov);
        const result = await builder.verify(body, hmacSecret);
        json(res, result.valid ? 200 : 400, result);
        return;
      }

      // ─── Boot Pre-flight ──────────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/boot/preflight")) {
        const { SecureBoot } = await import("../engine/boot");
        const result = SecureBoot.verifyPreFlight(gov);
        json(res, result.ready ? 200 : 503, result);
        return;
      }

      // ─── Degradation Status ───────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/degradation")) {
        json(res, 200, {
          current_tier: 0,
          name: "full",
          contracts_loaded: gov.getContracts().length,
          audit_entries: gov.getAuditEntries().length,
        });
        return;
      }

      // ─── Attestation Challenge ──────────────────────────
      if (matchRoute(method, url, "POST", "/v1/attestation/challenge")) {
        const { AttestationService } = await import("../attestation/rats");
        const service = new AttestationService();
        const body = JSON.parse(await parseBody(req));
        const scope = body.scope as string[] | undefined;
        const challenge = service.generateChallenge(scope);
        json(res, 200, challenge);
        return;
      }

      // ─── Attestation Verify ───────────────────────────────
      if (matchRoute(method, url, "POST", "/v1/attestation/verify")) {
        const { AttestationService } = await import("../attestation/rats");
        const service = new AttestationService();
        const body = JSON.parse(await parseBody(req));
        const { evidence, challenge } = body;
        if (!evidence || !challenge) {
          json(res, 400, { error: "bad_request", message: "evidence and challenge required" });
          return;
        }
        const result = service.verifyEvidence(evidence, challenge);
        json(res, 200, result);
        return;
      }

      // ─── Attestation Status ───────────────────────────────
      if (matchRoute(method, url, "GET", "/v1/attestation/status")) {
        const { AttestationService } = await import("../attestation/rats");
        const service = new AttestationService();
        const challenge = service.generateChallenge();
        const evidence = await service.collectEvidence(challenge, gov);
        const result = service.verifyEvidence(evidence, challenge);
        json(res, 200, {
          status: result.status,
          claims_verified: result.verified_claims.length,
          details: result.verified_claims,
        });
        return;
      }

      // ─── 404 ────────────────────────────────────────────
      json(res, 404, { error: "not_found", message: `${method} ${url} not found` });
    } catch (err: any) {
      log("error", `Request error: ${err.message}`);
      json(res, 500, { error: "internal_error", message: err.message });
    }
  });

  // Load contracts on init
  loadContracts();

  return {
    gov,
    start: () =>
      new Promise<void>((resolve) => {
        httpServer.listen(port, () => {
          log("info", `God Clause server listening on port ${port}`);
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
