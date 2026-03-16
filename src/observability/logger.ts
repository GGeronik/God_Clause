export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export interface LoggerOptions {
  level?: LogLevel;
  service?: string;
}

/**
 * Structured JSON logger compatible with ELK, Splunk, Datadog, and Loki.
 *
 * ```ts
 * const logger = new Logger({ level: "info", service: "god-clause" });
 * logger.info("Contract loaded", { name: "My Policy", version: "1.0.0" });
 * // {"level":"info","msg":"Contract loaded","name":"My Policy","version":"1.0.0","service":"god-clause","ts":"..."}
 * ```
 */
export class Logger {
  private level: LogLevel;
  private service: string;

  constructor(opts: LoggerOptions = {}) {
    this.level = opts.level ?? ((process.env.LOG_LEVEL as LogLevel) || "info");
    this.service = opts.service ?? "god-clause";
  }

  debug(msg: string, fields?: Record<string, unknown>): void {
    this.log("debug", msg, fields);
  }

  info(msg: string, fields?: Record<string, unknown>): void {
    this.log("info", msg, fields);
  }

  warn(msg: string, fields?: Record<string, unknown>): void {
    this.log("warn", msg, fields);
  }

  error(msg: string, fields?: Record<string, unknown>): void {
    this.log("error", msg, fields);
  }

  private log(level: LogLevel, msg: string, fields?: Record<string, unknown>): void {
    if (LEVEL_ORDER[level] < LEVEL_ORDER[this.level]) return;

    const entry = {
      level,
      msg,
      ...fields,
      service: this.service,
      ts: new Date().toISOString(),
    };

    const output = JSON.stringify(entry);
    if (level === "error") {
      process.stderr.write(output + "\n");
    } else {
      process.stdout.write(output + "\n");
    }
  }
}
