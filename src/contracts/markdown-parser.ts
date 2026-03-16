import { parseContract } from "./parser";
import type { TrustContract } from "../types";

/**
 * A section within a parsed markdown contract document.
 */
export interface MarkdownSection {
  /** Section type: prose text, embedded contract YAML/JSON, or example code. */
  type: "prose" | "contract" | "example";
  /** Raw content of the section. */
  content: string;
  /** Starting line number (1-based). */
  line_start: number;
  /** Ending line number (1-based, inclusive). */
  line_end: number;
}

/**
 * Result of parsing a markdown contract document.
 */
export interface MarkdownContractResult {
  /** The parsed trust contract extracted from the first YAML/JSON code block. */
  contract: TrustContract;
  /** The full markdown prose (all non-contract sections concatenated). */
  prose: string;
  /** All sections in document order. */
  sections: MarkdownSection[];
}

/**
 * Parse a markdown document containing an embedded trust contract.
 *
 * The parser extracts fenced code blocks (```yaml, ```json, or ```god-clause)
 * and attempts to parse them as trust contracts. The first valid trust contract
 * found becomes the result. All other content is preserved as prose sections.
 *
 * @param markdown - The markdown source text
 * @returns The parsed contract, prose text, and section breakdown
 * @throws Error if no valid trust contract is found in any code block
 */
export function parseMarkdownContract(markdown: string): MarkdownContractResult {
  const lines = markdown.split("\n");
  const sections: MarkdownSection[] = [];
  let contract: TrustContract | null = null;
  let contractError: Error | null = null;

  let i = 0;
  let proseStart = 1;
  let proseLines: string[] = [];

  while (i < lines.length) {
    const line = lines[i];
    const fenceMatch = line.match(/^```(yaml|json|god-clause)\s*$/i);

    if (fenceMatch) {
      // Flush accumulated prose
      if (proseLines.length > 0) {
        sections.push({
          type: "prose",
          content: proseLines.join("\n"),
          line_start: proseStart,
          line_end: i, // 1-based: line before this fence
        });
        proseLines = [];
      }

      const lang = fenceMatch[1].toLowerCase();
      const blockStart = i + 1; // 1-based line number
      const codeLines: string[] = [];
      i++;

      // Collect until closing fence
      while (i < lines.length && !lines[i].match(/^```\s*$/)) {
        codeLines.push(lines[i]);
        i++;
      }

      const blockEnd = i + 1; // 1-based, inclusive of closing fence
      const codeContent = codeLines.join("\n");

      // Try to parse as trust contract
      if (!contract && (lang === "yaml" || lang === "json" || lang === "god-clause")) {
        try {
          contract = parseContract(codeContent);
          sections.push({
            type: "contract",
            content: codeContent,
            line_start: blockStart,
            line_end: blockEnd,
          });
        } catch (err) {
          contractError = err instanceof Error ? err : new Error(String(err));
          // Not a valid contract — treat as example
          sections.push({
            type: "example",
            content: codeContent,
            line_start: blockStart,
            line_end: blockEnd,
          });
        }
      } else {
        // Already have a contract or not a contract language
        sections.push({
          type: "example",
          content: codeContent,
          line_start: blockStart,
          line_end: blockEnd,
        });
      }

      i++; // Skip closing fence
      proseStart = i + 1; // 1-based
    } else {
      proseLines.push(line);
      i++;
    }
  }

  // Flush remaining prose
  if (proseLines.length > 0) {
    sections.push({
      type: "prose",
      content: proseLines.join("\n"),
      line_start: proseStart,
      line_end: lines.length,
    });
  }

  if (!contract) {
    const detail = contractError ? `: ${contractError.message}` : "";
    throw new Error(`No valid trust contract found in markdown document${detail}`);
  }

  // Build prose from all prose sections
  const prose = sections
    .filter((s) => s.type === "prose")
    .map((s) => s.content)
    .join("\n\n");

  return { contract, prose, sections };
}
