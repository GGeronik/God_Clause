import { v4 as uuidv4 } from "uuid";
import { TraceContext, SpanType } from "../types";

/**
 * Builder for hierarchical trace spans.
 * Creates parent-child span relationships for correlating
 * multiple policy decisions within a single agent run or request.
 */
export class TraceBuilder {
  readonly traceId: string;

  constructor(traceId?: string) {
    this.traceId = traceId ?? uuidv4();
  }

  /** Create a root span (no parent). */
  rootSpan(type?: SpanType): TraceContext {
    return {
      trace_id: this.traceId,
      span_id: uuidv4(),
      span_type: type,
    };
  }

  /** Create a child span under a parent. */
  childSpan(parent: TraceContext, type?: SpanType): TraceContext {
    return {
      trace_id: this.traceId,
      span_id: uuidv4(),
      parent_span_id: parent.span_id,
      span_type: type,
    };
  }
}
