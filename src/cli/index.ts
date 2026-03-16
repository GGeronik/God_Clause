#!/usr/bin/env node

import { Command } from "commander";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve } from "path";
import { parseContract, summarizeContract, serializeContract, ContractParseError } from "../contracts/parser";
import { lintContract, LintResult } from "./linter";
import { GodClause } from "../governance";
import { MemoryStateStore } from "../engine/state-store";
import { AuditLog, MemoryAuditSink } from "../audit/audit-log";
import type { AuditEntry } from "../types";

const program = new Command();

program.name("god-clause").description("God Clause — Embeddable AI Governance Framework CLI").version("2.0.0");

// ─── validate ───────────────────────────────────────────────────────
program
  .command("validate")
  .description("Validate a trust contract against the schema")
  .argument("<file>", "Path to contract YAML/JSON file")
  .action((file: string) => {
    const path = resolve(file);
    if (!existsSync(path)) {
      console.error(`Error: File not found: ${path}`);
      process.exit(1);
    }
    const source = readFileSync(path, "utf-8");
    try {
      parseContract(source);
      console.log(`Valid: ${file}`);
    } catch (err) {
      if (err instanceof ContractParseError) {
        console.error(`Invalid: ${file}`);
        for (const e of err.errors) {
          console.error(`  - ${e}`);
        }
        process.exit(1);
      }
      throw err;
    }
  });

// ─── lint ───────────────────────────────────────────────────────────
program
  .command("lint")
  .description("Check a trust contract for best practices")
  .argument("<file>", "Path to contract YAML/JSON file")
  .action((file: string) => {
    const path = resolve(file);
    if (!existsSync(path)) {
      console.error(`Error: File not found: ${path}`);
      process.exit(1);
    }
    const source = readFileSync(path, "utf-8");
    let contract;
    try {
      contract = parseContract(source);
    } catch (err) {
      if (err instanceof ContractParseError) {
        console.error(`Cannot lint — contract has schema errors:`);
        for (const e of err.errors) {
          console.error(`  - ${e}`);
        }
        process.exit(1);
      }
      throw err;
    }

    const results = lintContract(contract);
    if (results.length === 0) {
      console.log(`No issues found in ${file}`);
      return;
    }

    const errors = results.filter((r) => r.severity === "error");
    const warnings = results.filter((r) => r.severity === "warning");

    for (const r of results) {
      const icon = r.severity === "error" ? "ERROR" : "WARN";
      const ruleRef = r.ruleId ? ` [${r.ruleId}]` : "";
      console.log(`  ${icon}: ${r.message}${ruleRef}`);
    }

    console.log(`\n${errors.length} error(s), ${warnings.length} warning(s)`);
    if (errors.length > 0) process.exit(1);
  });

// ─── summarize ──────────────────────────────────────────────────────
program
  .command("summarize")
  .description("Print a plain-language summary of a trust contract")
  .argument("<file>", "Path to contract YAML/JSON file")
  .action((file: string) => {
    const path = resolve(file);
    const source = readFileSync(path, "utf-8");
    const contract = parseContract(source);
    console.log(summarizeContract(contract));
  });

// ─── diff ───────────────────────────────────────────────────────────
program
  .command("diff")
  .description("Compare two contract versions side by side")
  .argument("<file1>", "Path to first contract")
  .argument("<file2>", "Path to second contract")
  .action((file1: string, file2: string) => {
    const c1 = parseContract(readFileSync(resolve(file1), "utf-8"));
    const c2 = parseContract(readFileSync(resolve(file2), "utf-8"));

    console.log(
      `Comparing: ${c1.metadata.name} v${c1.metadata.version} → ${c2.metadata.name} v${c2.metadata.version}\n`,
    );

    // Compare rules
    const rules1 = new Map(c1.rules.map((r) => [r.id, r]));
    const rules2 = new Map(c2.rules.map((r) => [r.id, r]));

    const added: string[] = [];
    const removed: string[] = [];
    const changed: string[] = [];

    for (const [id] of rules2) {
      if (!rules1.has(id)) added.push(id);
    }
    for (const [id] of rules1) {
      if (!rules2.has(id)) removed.push(id);
    }
    for (const [id, r2] of rules2) {
      const r1 = rules1.get(id);
      if (r1 && JSON.stringify(r1) !== JSON.stringify(r2)) {
        changed.push(id);
      }
    }

    if (added.length) {
      console.log("Added rules:");
      for (const id of added) console.log(`  + ${id}: ${rules2.get(id)!.description}`);
    }
    if (removed.length) {
      console.log("Removed rules:");
      for (const id of removed) console.log(`  - ${id}: ${rules1.get(id)!.description}`);
    }
    if (changed.length) {
      console.log("Changed rules:");
      for (const id of changed) {
        const r1 = rules1.get(id)!;
        const r2 = rules2.get(id)!;
        console.log(`  ~ ${id}: ${r2.description}`);
        if (r1.on_violation !== r2.on_violation) {
          console.log(`    severity: ${r1.on_violation} → ${r2.on_violation}`);
        }
        if (JSON.stringify(r1.conditions) !== JSON.stringify(r2.conditions)) {
          console.log(`    conditions: modified`);
        }
        if (JSON.stringify(r1.action) !== JSON.stringify(r2.action)) {
          console.log(`    actions: ${JSON.stringify(r1.action)} → ${JSON.stringify(r2.action)}`);
        }
      }
    }

    if (!added.length && !removed.length && !changed.length) {
      // Check metadata/data_governance
      if (JSON.stringify(c1.metadata) !== JSON.stringify(c2.metadata)) {
        console.log("Metadata changed");
      }
      if (JSON.stringify(c1.data_governance) !== JSON.stringify(c2.data_governance)) {
        console.log("Data governance changed");
      }
      if (JSON.stringify(c1) === JSON.stringify(c2)) {
        console.log("No differences found");
      }
    }

    console.log(`\nSummary: +${added.length} added, -${removed.length} removed, ~${changed.length} changed`);
  });

// ─── evaluate ───────────────────────────────────────────────────────
program
  .command("evaluate")
  .description("Evaluate a context against a contract (one-shot)")
  .argument("<file>", "Path to contract YAML/JSON file")
  .requiredOption("--context <json>", "Policy context as JSON string or path to JSON file")
  .option("--include-tags <tags...>", "Only evaluate rules with these tags")
  .option("--exclude-tags <tags...>", "Skip rules with these tags")
  .action(async (file: string, opts: { context: string; includeTags?: string[]; excludeTags?: string[] }) => {
    const contract = parseContract(readFileSync(resolve(file), "utf-8"));

    let contextData: string;
    if (existsSync(resolve(opts.context))) {
      contextData = readFileSync(resolve(opts.context), "utf-8");
    } else {
      contextData = opts.context;
    }

    const ctx = JSON.parse(contextData);
    const gov = new GodClause({ stateStore: new MemoryStateStore() });
    gov.loadContract(contract);

    const evalOpts: Record<string, unknown> = {};
    if (opts.includeTags) evalOpts.includeTags = opts.includeTags;
    if (opts.excludeTags) evalOpts.excludeTags = opts.excludeTags;

    const decision = await gov.evaluate(ctx, evalOpts as any);

    console.log(
      JSON.stringify(
        {
          decision_id: decision.decision_id,
          outcome: decision.outcome,
          allowed: decision.allowed,
          blocks: decision.blocks.map((b) => ({ rule_id: b.rule_id, description: b.rule_description })),
          warnings: decision.warnings.map((w) => ({ rule_id: w.rule_id, description: w.rule_description })),
          obligations: decision.obligations.map((o) => ({ id: o.obligation_id, type: o.type })),
          governance_context: decision.governance_context,
        },
        null,
        2,
      ),
    );
  });

// ─── audit verify ───────────────────────────────────────────────────
const auditCmd = program.command("audit").description("Audit log operations");

auditCmd
  .command("verify")
  .description("Verify hash chain integrity of an audit JSONL file")
  .argument("<file>", "Path to audit JSONL file")
  .option("--secret <key>", "HMAC secret key for signature verification")
  .action((file: string, opts: { secret?: string }) => {
    const path = resolve(file);
    const lines = readFileSync(path, "utf-8").trim().split("\n");
    const entries: AuditEntry[] = lines.map((line) => JSON.parse(line));

    const auditLog = new AuditLog();
    const result = auditLog.verifyChain(entries, opts.secret);

    if (result.valid) {
      console.log(`Valid: ${entries.length} entries, hash chain intact`);
    } else {
      console.error(`INVALID: Hash chain broken at entry ${result.brokenAt}`);
      if (result.brokenAt !== undefined) {
        console.error(`  Entry ID: ${entries[result.brokenAt].entry_id}`);
        console.error(`  Timestamp: ${entries[result.brokenAt].timestamp}`);
      }
      process.exit(1);
    }
  });

auditCmd
  .command("export")
  .description("Export audit log to CSV or JSON")
  .argument("<file>", "Path to audit JSONL file")
  .option("--format <format>", "Output format: csv or json", "json")
  .option("--output <file>", "Output file (default: stdout)")
  .action((file: string, opts: { format: string; output?: string }) => {
    const path = resolve(file);
    const lines = readFileSync(path, "utf-8").trim().split("\n");
    const entries: AuditEntry[] = lines.map((line) => JSON.parse(line));

    let output: string;
    if (opts.format === "csv") {
      const headers = [
        "entry_id",
        "decision_id",
        "timestamp",
        "action",
        "allowed",
        "outcome",
        "contract_name",
        "user_id",
        "blocks",
        "warnings",
      ];
      const rows = entries.map((e) =>
        [
          e.entry_id,
          e.decision_id,
          e.timestamp,
          e.action,
          e.allowed,
          e.outcome ?? "",
          e.contract_name,
          e.caller.user_id,
          e.blocks.join(";"),
          e.warnings.join(";"),
        ]
          .map((v) => `"${String(v).replace(/"/g, '""')}"`)
          .join(","),
      );
      output = [headers.join(","), ...rows].join("\n");
    } else {
      output = JSON.stringify(entries, null, 2);
    }

    if (opts.output) {
      writeFileSync(resolve(opts.output), output);
      console.log(`Exported ${entries.length} entries to ${opts.output}`);
    } else {
      console.log(output);
    }
  });

// ─── serve ──────────────────────────────────────────────────────────
program
  .command("serve")
  .description("Start the God Clause REST API server")
  .option("--port <port>", "Port to listen on", "3000")
  .option("--contracts <dir>", "Directory to load contracts from", "./contracts")
  .option("--audit-dir <dir>", "Directory for audit JSONL files")
  .option("--hmac-secret <key>", "HMAC secret key for audit signing")
  .option("--log-level <level>", "Log level (debug, info, warn, error)", "info")
  .action(
    async (opts: { port: string; contracts: string; auditDir?: string; hmacSecret?: string; logLevel: string }) => {
      const { createServer } = await import("../server/server");
      const server = createServer({
        port: parseInt(opts.port, 10),
        contractsDir: resolve(opts.contracts),
        auditDir: opts.auditDir ? resolve(opts.auditDir) : undefined,
        hmacSecret: opts.hmacSecret,
        logLevel: opts.logLevel as any,
      });
      await server.start();
    },
  );

// ─── init ───────────────────────────────────────────────────────────
program
  .command("init")
  .description("Create a new trust contract from a template")
  .option("--name <name>", "Contract name", "My AI Policy")
  .option("--output <file>", "Output file", "contract.yaml")
  .action((opts: { name: string; output: string }) => {
    const template = `schema_version: "1.0"

metadata:
  name: "${opts.name}"
  version: "1.0.0"
  author: Your Team
  description: >
    Describe what this contract governs and the AI system it applies to.
  effective_date: "${new Date().toISOString().split("T")[0]}"
  review_date: "${new Date(Date.now() + 180 * 86400000).toISOString().split("T")[0]}"
  stakeholders:
    - Engineering Lead
    - Compliance Officer

data_governance:
  allowed_input_classes:
    - public
    - internal
  allowed_output_classes:
    - public
  retention_period: P30D
  cross_border_transfer: false

rules:
  - id: SAFETY-001
    description: Block outputs with high toxicity scores
    action: generate
    conditions:
      - field: output.toxicity_score
        operator: less_than
        value: 0.7
    on_violation: block
    tags:
      - safety
      - content-moderation

  - id: QUALITY-001
    description: Warn when confidence is below threshold
    action: "*"
    conditions:
      - field: output.confidence
        operator: greater_than
        value: 0.8
    on_violation: warn
    tags:
      - quality

  - id: AUDIT-001
    description: Log all model outputs for audit trail
    action: "*"
    conditions:
      - field: output
        operator: exists
        value: true
    on_violation: log
    tags:
      - audit
`;

    const outPath = resolve(opts.output);
    writeFileSync(outPath, template);
    console.log(`Created: ${outPath}`);
    console.log(`\nNext steps:`);
    console.log(`  god-clause validate ${opts.output}`);
    console.log(`  god-clause lint ${opts.output}`);
    console.log(`  god-clause summarize ${opts.output}`);
  });

// ─── generate ───────────────────────────────────────────────────────
program
  .command("generate")
  .description("Generate a trust contract from a built-in template")
  .requiredOption(
    "--template <id>",
    "Template ID (pii-protection, rate-limiting, content-safety, access-control, model-governance, compliance-baseline)",
  )
  .option("--params <json>", "Template parameters as JSON string", "{}")
  .option("--name <name>", "Contract name override")
  .option("--output <file>", "Output file (default: stdout)")
  .action(async (opts: { template: string; params: string; name?: string; output?: string }) => {
    const { P2TGenerator } = await import("../contracts/p2t-generator");
    const gen = new P2TGenerator();

    try {
      const params = JSON.parse(opts.params);
      const yaml = gen.generate({
        template: opts.template,
        params,
        metadata: opts.name ? { name: opts.name } : undefined,
      });

      if (opts.output) {
        writeFileSync(resolve(opts.output), yaml);
        console.log(`Generated: ${opts.output}`);
      } else {
        console.log(yaml);
      }
    } catch (err) {
      console.error(`Error: ${(err as Error).message}`);
      process.exit(1);
    }
  });

// ─── proof-bundle ───────────────────────────────────────────────────
program
  .command("proof-bundle")
  .description("Export a cryptographic proof bundle from contracts and audit log")
  .option("--contracts <dir>", "Directory with contract YAML files", "./contracts")
  .option("--audit <file>", "Audit JSONL file to include")
  .option("--output <file>", "Output file (default: stdout)")
  .option("--from <date>", "Start date filter (ISO 8601)")
  .option("--to <date>", "End date filter (ISO 8601)")
  .action(async (opts: { contracts: string; audit?: string; output?: string; from?: string; to?: string }) => {
    const { ProofBundleBuilder } = await import("../audit/proof-bundle");
    const { readdirSync } = await import("fs");

    const gov = new GodClause();
    const dir = resolve(opts.contracts);

    // Load contracts
    if (existsSync(dir)) {
      const files = readdirSync(dir).filter(
        (f: string) => f.endsWith(".yaml") || f.endsWith(".yml") || f.endsWith(".json"),
      );
      for (const f of files) {
        try {
          gov.loadContractYAML(readFileSync(resolve(dir, f), "utf-8"));
        } catch {
          /* skip invalid */
        }
      }
    }

    const builder = new ProofBundleBuilder(gov);
    const bundle = await builder.build({ from: opts.from, to: opts.to });
    const json = await builder.exportJSON(bundle);

    if (opts.output) {
      writeFileSync(resolve(opts.output), json);
      console.log(`Proof bundle exported: ${opts.output} (${bundle.audit_entries.length} entries)`);
    } else {
      console.log(json);
    }
  });

// ─── verify-bundle ──────────────────────────────────────────────────
program
  .command("verify-bundle")
  .description("Verify a proof bundle's cryptographic integrity")
  .argument("<file>", "Path to proof bundle JSON file")
  .option("--secret <key>", "HMAC secret key for signature verification")
  .action(async (file: string, opts: { secret?: string }) => {
    const { ProofBundleBuilder } = await import("../audit/proof-bundle");
    const path = resolve(file);
    const bundleData = JSON.parse(readFileSync(path, "utf-8"));

    const gov = new GodClause();
    const builder = new ProofBundleBuilder(gov);
    const result = await builder.verify(bundleData, opts.secret);

    if (result.valid) {
      console.log(`VALID: Proof bundle verified`);
      console.log(`  Chain: ${result.chain_valid ? "✓" : "✗"}`);
      console.log(`  Seals: ${result.seals_valid ? "✓" : "✗"}`);
      for (const d of result.details) {
        console.log(`  ${d.passed ? "✓" : "✗"} ${d.check}: ${d.detail || ""}`);
      }
    } else {
      console.error(`INVALID: Proof bundle verification failed`);
      for (const d of result.details) {
        console.error(`  ${d.passed ? "✓" : "✗"} ${d.check}: ${d.detail || ""}`);
      }
      process.exit(1);
    }
  });

// ─── boot ───────────────────────────────────────────────────────────
program
  .command("boot")
  .description("Perform a secure boot pre-flight check")
  .option("--contracts <dir>", "Directory with contract YAML files", "./contracts")
  .option("--require-signatures", "Fail if any contract is unsigned")
  .option("--audit-dir <dir>", "Directory for audit files")
  .action(async (opts: { contracts: string; requireSignatures?: boolean; auditDir?: string }) => {
    const { SecureBoot } = await import("../engine/boot");
    const { readdirSync } = await import("fs");
    const dir = resolve(opts.contracts);

    const contractSources: string[] = [];
    if (existsSync(dir)) {
      const files = readdirSync(dir).filter(
        (f: string) => f.endsWith(".yaml") || f.endsWith(".yml") || f.endsWith(".json"),
      );
      for (const f of files) {
        contractSources.push(readFileSync(resolve(dir, f), "utf-8"));
      }
    }

    const { gov, preflight } = await SecureBoot.initialize({
      contracts: contractSources,
      requireSignatures: opts.requireSignatures,
    });

    console.log(`Pre-flight: ${preflight.ready ? "READY" : "DEGRADED"} (tier ${preflight.degradation_tier})`);
    for (const check of preflight.checks) {
      console.log(`  ${check.passed ? "✓" : "✗"} ${check.name}${check.detail ? ": " + check.detail : ""}`);
    }

    if (!preflight.ready) {
      process.exit(1);
    }
  });

// ─── tlaplus ──────────────────────────────────────────────────────
program
  .command("tlaplus")
  .description("Generate a TLA+ specification from a trust contract for formal verification")
  .argument("<file>", "Path to contract YAML/JSON file")
  .option("--output <dir>", "Output directory for .tla and .cfg files")
  .option("--check", "Run TLC model checker (requires Java + tla2tools.jar)")
  .option("--tlc-path <path>", "Path to tla2tools.jar")
  .action(async (file: string, opts: { output?: string; check?: boolean; tlcPath?: string }) => {
    const { TLAPlusGenerator } = await import("../compliance/tlaplus-generator");
    const path = resolve(file);
    if (!existsSync(path)) {
      console.error(`Error: File not found: ${path}`);
      process.exit(1);
    }

    try {
      const source = readFileSync(path, "utf-8");
      const contract = parseContract(source);
      const gen = new TLAPlusGenerator({ tlcPath: opts.tlcPath, outputDir: opts.output });
      const spec = gen.generate(contract);

      if (opts.output) {
        const { mkdirSync } = require("fs");
        mkdirSync(opts.output, { recursive: true });
        writeFileSync(resolve(opts.output, `${spec.moduleName}.tla`), spec.specContent);
        writeFileSync(resolve(opts.output, `${spec.moduleName}.cfg`), spec.configContent);
        console.log(`Generated: ${spec.moduleName}.tla, ${spec.moduleName}.cfg`);
        console.log(`Invariants: ${spec.invariants.join(", ")}`);
        console.log(`Properties: ${spec.properties.join(", ")}`);
      } else {
        console.log(spec.specContent);
      }

      if (opts.check) {
        console.log("\nRunning TLC model checker...");
        const result = await gen.runModelChecker(spec);
        console.log(`Status: ${result.status}`);
        if (result.statesExplored) console.log(`States explored: ${result.statesExplored}`);
        if (result.counterexample) console.log(`Counterexample: ${result.counterexample}`);
        if (result.status === "unavailable") {
          console.log("TLC not available. Install Java and download tla2tools.jar.");
        }
      }
    } catch (err) {
      console.error(`Error: ${err instanceof Error ? err.message : err}`);
      process.exit(1);
    }
  });

// ─── attest ─────────────────────────────────────────────────────────
program
  .command("attest")
  .description("Run remote attestation checks against loaded contracts")
  .option("--contracts <dir>", "Directory containing trust contract files", ".")
  .option("--scope <claims>", "Comma-separated claim types to attest", "contract_hash,audit_chain,system_state")
  .action(async (opts: { contracts: string; scope: string }) => {
    const { AttestationService } = await import("../attestation/rats");
    const { readdirSync } = require("fs");

    const service = new AttestationService();
    const scope = opts.scope.split(",").map((s: string) => s.trim());

    // Load contracts
    const dir = resolve(opts.contracts);
    const gov = new GodClause();
    if (existsSync(dir)) {
      const files = readdirSync(dir).filter(
        (f: string) => f.endsWith(".yaml") || f.endsWith(".yml") || f.endsWith(".json"),
      );
      for (const f of files) {
        try {
          const source = readFileSync(resolve(dir, f), "utf-8");
          gov.loadContractYAML(source);
        } catch {
          /* skip invalid files */
        }
      }
    }

    // Run attestation
    const challenge = service.generateChallenge(scope);
    console.log(`Challenge nonce: ${challenge.nonce.slice(0, 16)}...`);

    const evidence = await service.collectEvidence(challenge, gov);
    console.log(`Evidence collected: ${evidence.claims.length} claims`);
    for (const claim of evidence.claims) {
      console.log(`  ${claim.type}: ${JSON.stringify(claim.value).slice(0, 80)}`);
    }

    const result = service.verifyEvidence(evidence, challenge);
    console.log(`\nVerification: ${result.status.toUpperCase()}`);
    for (const vc of result.verified_claims) {
      console.log(`  ${vc.verified ? "✓" : "✗"} ${vc.type}${vc.detail ? ": " + vc.detail : ""}`);
    }

    if (result.status !== "success") {
      process.exit(1);
    }
  });

program.parse();
