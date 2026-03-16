import type { IncomingMessage, ServerResponse } from "http";
import { GodClause } from "../governance";
import { PolicyContext, PolicyDecision } from "../types";

export interface HttpMiddlewareOptions {
  /** Extract a PolicyContext from the incoming request. */
  contextExtractor: (req: IncomingMessage) => PolicyContext | Promise<PolicyContext>;
  /** Called when the action is blocked. Defaults to 403 JSON response. */
  onBlock?: (res: ServerResponse, decision: PolicyDecision) => void;
  /** Called when warnings are present but action is allowed. Defaults to setting headers. */
  onWarn?: (res: ServerResponse, decision: PolicyDecision) => void;
  /** Attach the decision to the request object under this key. Default: 'godClauseDecision'. */
  decisionKey?: string;
}

/**
 * Create HTTP middleware compatible with Express, Fastify (raw mode), and any
 * Node.js HTTP framework that uses (req, res, next) signatures.
 *
 * ```ts
 * app.use(godClauseMiddleware(gov, {
 *   contextExtractor: (req) => ({
 *     action: "generate",
 *     input: { prompt: req.body.prompt },
 *     caller: { user_id: req.user.id, session_id: req.sessionID, roles: req.user.roles },
 *   }),
 * }));
 * ```
 */
export function godClauseMiddleware(gov: GodClause, opts: HttpMiddlewareOptions) {
  const decisionKey = opts.decisionKey ?? "godClauseDecision";

  return async (req: any, res: any, next: (...args: any[]) => void) => {
    try {
      const ctx = await opts.contextExtractor(req);
      const decision = await gov.evaluate(ctx);

      req[decisionKey] = decision;

      if (!decision.allowed) {
        if (opts.onBlock) {
          opts.onBlock(res, decision);
        } else {
          res.statusCode = 403;
          res.setHeader("Content-Type", "application/json");
          res.end(
            JSON.stringify({
              error: "Policy violation",
              decision_id: decision.decision_id,
              blocks: decision.blocks.map((b) => ({
                rule_id: b.rule_id,
                description: b.rule_description,
              })),
            }),
          );
        }
        return;
      }

      if (decision.warnings.length > 0) {
        res.setHeader("X-GodClause-Warnings", decision.warnings.map((w) => w.rule_id).join(","));
        if (opts.onWarn) opts.onWarn(res, decision);
      }

      next();
    } catch (err) {
      next(err);
    }
  };
}
