import type {
  PolicyContext,
  PolicyDecision,
  CallerInfo,
  ActionVerb,
  Obligation,
} from "../types";

// Duck-typed interface to avoid coupling to the concrete GodClause class.
export interface GovernanceEvaluator {
  evaluate(ctx: PolicyContext): Promise<PolicyDecision>;
}

export interface GovernedStreamOptions {
  gov: GovernanceEvaluator;
  caller: CallerInfo;
  action?: ActionVerb; // default: "generate"
  boundary?: "sentence" | "chars"; // default: "sentence"
  charThreshold?: number; // default: 200, for "chars" mode
  /** Takes text, returns output fields for policy context (e.g., PII flags) */
  detectFields?: (text: string) => Record<string, unknown>;
  /** Takes text + obligations, returns cleaned text */
  applyObligations?: (text: string, obligations: Obligation[]) => string;
  metadata?: Record<string, unknown>;
}

// Sentence-ending pattern: punctuation followed by whitespace.
const SENTENCE_END_RE = /[.!?]\s/;

export class GovernedStream {
  private readonly gov: GovernanceEvaluator;
  private readonly caller: CallerInfo;
  private readonly action: ActionVerb;
  private readonly boundary: "sentence" | "chars";
  private readonly charThreshold: number;
  private readonly detectFields?: (text: string) => Record<string, unknown>;
  private readonly applyObligationsFn?: (text: string, obligations: Obligation[]) => string;
  private readonly metadata?: Record<string, unknown>;

  constructor(opts: GovernedStreamOptions) {
    this.gov = opts.gov;
    this.caller = opts.caller;
    this.action = opts.action ?? "generate";
    this.boundary = opts.boundary ?? "sentence";
    this.charThreshold = opts.charThreshold ?? 200;
    this.detectFields = opts.detectFields;
    this.applyObligationsFn = opts.applyObligations;
    this.metadata = opts.metadata;
  }

  /**
   * Evaluate a text segment against governance policies and apply obligations.
   */
  private async evaluateSegment(segment: string): Promise<string> {
    const fields = this.detectFields ? this.detectFields(segment) : {};

    const ctx: PolicyContext = {
      action: this.action,
      input: {},
      output: { text: segment, ...fields },
      caller: this.caller,
      metadata: this.metadata,
    };

    const decision = await this.gov.evaluate(ctx);

    if (decision.obligations.length > 0 && this.applyObligationsFn) {
      return this.applyObligationsFn(segment, decision.obligations);
    }

    return segment;
  }

  /**
   * Extract complete sentences from the buffer.
   * Returns [segmentsToEvaluate, remainingBuffer].
   */
  private extractSentences(buffer: string): [string[], string] {
    const segments: string[] = [];
    let remaining = buffer;

    // Find sentence boundaries: punctuation followed by whitespace.
    let match: RegExpExecArray | null;
    while ((match = SENTENCE_END_RE.exec(remaining)) !== null) {
      // Include the punctuation but not the trailing whitespace.
      const endIndex = match.index + 1;
      segments.push(remaining.slice(0, endIndex));
      remaining = remaining.slice(endIndex).trimStart();
    }

    return [segments, remaining];
  }

  /**
   * Extract a segment from the buffer using char threshold with overlap.
   * Returns [segmentToEvaluate, remainingBuffer] or [null, buffer] if not enough.
   */
  private extractByChars(buffer: string): [string | null, string] {
    if (buffer.length < this.charThreshold) {
      return [null, buffer];
    }

    // Extract up to charThreshold, but keep up to 20-char overlap in buffer.
    // Clamp overlap so we always make forward progress.
    const overlapSize = Math.min(20, this.charThreshold - 1);
    const extractEnd = this.charThreshold;
    const segment = buffer.slice(0, extractEnd);
    // Leave the last `overlapSize` chars of the extracted segment in the buffer
    // so PII patterns split across boundaries can be caught.
    const newBufferStart = extractEnd - overlapSize;
    const remaining = buffer.slice(newBufferStart);

    return [segment, remaining];
  }

  /**
   * Process an async iterable of string chunks, yielding governed chunks.
   */
  async *govern(source: AsyncIterable<string>): AsyncGenerator<string> {
    let buffer = "";

    for await (const chunk of source) {
      if (chunk.length === 0) continue;

      buffer += chunk;

      if (this.boundary === "sentence") {
        const [segments, remaining] = this.extractSentences(buffer);
        buffer = remaining;

        for (const segment of segments) {
          const governed = await this.evaluateSegment(segment);
          yield governed;
        }
      } else {
        // chars mode
        let segment: string | null;
        [segment, buffer] = this.extractByChars(buffer);
        while (segment !== null) {
          const governed = await this.evaluateSegment(segment);
          yield governed;
          [segment, buffer] = this.extractByChars(buffer);
        }
      }
    }

    // Flush remaining buffer.
    if (buffer.length > 0) {
      const governed = await this.evaluateSegment(buffer);
      yield governed;
    }
  }
}

export function createGovernedStream(opts: GovernedStreamOptions): GovernedStream {
  return new GovernedStream(opts);
}
