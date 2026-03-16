import { GodClause } from "../governance";
import {
  PolicyContext,
  PolicyDecision,
  CallerInfo,
  ActionVerb,
} from "../types";
import { PolicyViolationError } from "../engine/policy-engine";

// ─── Generic AI Hook ─────────────────────────────────────────────────

export interface AIInvocationHook {
  /** Called before the model is invoked. Throws PolicyViolationError if blocked. */
  beforeInvoke(params: {
    action?: ActionVerb;
    model?: string;
    prompt: unknown;
    caller: CallerInfo;
    metadata?: Record<string, unknown>;
  }): Promise<PolicyDecision>;

  /** Called after the model responds. Throws PolicyViolationError if blocked. */
  afterInvoke(params: {
    action?: ActionVerb;
    model?: string;
    prompt: unknown;
    response: unknown;
    caller: CallerInfo;
    metadata?: Record<string, unknown>;
  }): Promise<PolicyDecision>;
}

export interface AIHookOptions {
  /** Default action verb for pre-invocation checks. Default: "generate". */
  defaultAction?: ActionVerb;
}

/**
 * Create a generic AI invocation hook that can be wired into any
 * AI SDK or custom model wrapper.
 */
export function createAIHook(
  gov: GodClause,
  opts: AIHookOptions = {},
): AIInvocationHook {
  const defaultAction = opts.defaultAction ?? "generate";

  return {
    async beforeInvoke(params) {
      const ctx: PolicyContext = {
        action: params.action ?? defaultAction,
        input: { prompt: params.prompt, model: params.model },
        caller: params.caller,
        metadata: params.metadata,
      };
      return gov.enforce(ctx);
    },

    async afterInvoke(params) {
      const ctx: PolicyContext = {
        action: params.action ?? defaultAction,
        input: { prompt: params.prompt, model: params.model },
        output: typeof params.response === "object" && params.response !== null
          ? params.response as Record<string, unknown>
          : { raw: params.response },
        caller: params.caller,
        metadata: params.metadata,
      };
      return gov.enforce(ctx);
    },
  };
}

// ─── LangChain Callback Handler (duck-typed) ─────────────────────────

export interface LangChainHandlerOptions {
  /** Caller info to attach to all evaluations. */
  caller: CallerInfo;
  /** Action verb for LLM calls. Default: "generate". */
  action?: ActionVerb;
}

/**
 * Create a LangChain-compatible callback handler via duck typing.
 * No `langchain` import required — conforms to the BaseCallbackHandler shape.
 *
 * ```ts
 * const handler = createLangChainCallbackHandler(gov, { caller: { ... } });
 * const chain = new LLMChain({ llm, callbacks: [handler] });
 * ```
 */
export function createLangChainCallbackHandler(
  gov: GodClause,
  opts: LangChainHandlerOptions,
) {
  const action = opts.action ?? "generate";

  return {
    name: "GodClauseHandler",

    async handleLLMStart(
      llm: { name?: string } | undefined,
      prompts: string[],
    ): Promise<void> {
      const ctx: PolicyContext = {
        action,
        input: { prompts, model: llm?.name },
        caller: opts.caller,
      };
      await gov.enforce(ctx);
    },

    async handleLLMEnd(output: {
      generations?: Array<Array<{ text?: string }>>;
    }): Promise<void> {
      const text = output?.generations?.[0]?.[0]?.text ?? "";
      const ctx: PolicyContext = {
        action,
        input: {},
        output: { text, raw: output },
        caller: opts.caller,
      };
      // Post-invocation: evaluate but don't enforce (response already generated)
      await gov.evaluate(ctx);
    },

    async handleLLMError(err: Error): Promise<void> {
      // Log the error via audit but don't interfere
      const ctx: PolicyContext = {
        action,
        input: {},
        output: { error: err.message },
        caller: opts.caller,
        metadata: { error: true },
      };
      await gov.evaluate(ctx);
    },
  };
}

// ─── Vercel AI SDK Wrapper ───────────────────────────────────────────

export interface VercelAIWrapperOptions {
  /** Caller info to attach to all evaluations. */
  caller: CallerInfo;
  /** Action verb. Default: "generate". */
  action?: ActionVerb;
}

/**
 * Create a wrapper for Vercel AI SDK model calls.
 *
 * ```ts
 * const wrapper = createVercelAIWrapper(gov, { caller: { ... } });
 * const result = await wrapper.wrapGenerate({
 *   doGenerate: () => model.doGenerate(params),
 *   prompt: params.prompt,
 * });
 * ```
 */
export function createVercelAIWrapper(
  gov: GodClause,
  opts: VercelAIWrapperOptions,
) {
  const action = opts.action ?? "generate";

  return {
    async wrapGenerate<T>(params: {
      prompt: unknown;
      model?: string;
      doGenerate: () => Promise<T>;
      metadata?: Record<string, unknown>;
    }): Promise<T> {
      // Pre-check
      const preCtx: PolicyContext = {
        action,
        input: { prompt: params.prompt, model: params.model },
        caller: opts.caller,
        metadata: params.metadata,
      };
      await gov.enforce(preCtx);

      // Execute
      const result = await params.doGenerate();

      // Post-check (evaluate only, response already generated)
      const postCtx: PolicyContext = {
        action,
        input: { prompt: params.prompt, model: params.model },
        output: typeof result === "object" && result !== null
          ? result as Record<string, unknown>
          : { raw: result },
        caller: opts.caller,
        metadata: params.metadata,
      };
      await gov.evaluate(postCtx);

      return result;
    },
  };
}
