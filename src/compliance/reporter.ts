import type { GodClause } from "../governance";
import type { AuditEntry, TrustContract } from "../types";

export type ComplianceFramework = "eu-ai-act" | "nist-ai-rmf" | "iso-42001" | "soc2" | "gdpr" | "hipaa";

export type ControlStatus = "satisfied" | "partial" | "not_addressed";

export interface ComplianceControl {
  control_id: string;
  description: string;
  status: ControlStatus;
  evidence: string[];
}

export interface ComplianceReport {
  framework: ComplianceFramework;
  generated_at: string;
  contract_summary: string;
  contracts_evaluated: number;
  audit_entries_evaluated: number;
  controls: ComplianceControl[];
  overall_status: ControlStatus;
}

export interface ReportOptions {
  dateRange?: { from: string; to: string };
}

/**
 * Generate a compliance report mapping God Clause features to
 * regulatory framework controls.
 *
 * ```ts
 * const report = generateComplianceReport(gov, "eu-ai-act");
 * console.log(report.controls);
 * ```
 */
export function generateComplianceReport(
  gov: GodClause,
  framework: ComplianceFramework,
  opts?: ReportOptions,
): ComplianceReport {
  const contracts = gov.getContracts();
  const entries = gov.getAuditEntries();

  let filteredEntries = [...entries];
  if (opts?.dateRange) {
    const from = new Date(opts.dateRange.from).getTime();
    const to = new Date(opts.dateRange.to).getTime();
    filteredEntries = filteredEntries.filter((e) => {
      const t = new Date(e.timestamp).getTime();
      return t >= from && t <= to;
    });
  }

  const controlDefs = getControlDefinitions(framework);
  const controls = controlDefs.map((def) => evaluateControl(def, contracts, filteredEntries));

  const statuses = controls.map((c) => c.status);
  let overall: ControlStatus = "satisfied";
  if (statuses.includes("not_addressed")) overall = "not_addressed";
  else if (statuses.includes("partial")) overall = "partial";

  const contractNames = contracts.map((c) => `${c.metadata.name} v${c.metadata.version}`);

  return {
    framework,
    generated_at: new Date().toISOString(),
    contract_summary:
      contractNames.length > 0 ? `Evaluated contracts: ${contractNames.join(", ")}` : "No contracts loaded",
    contracts_evaluated: contracts.length,
    audit_entries_evaluated: filteredEntries.length,
    controls,
    overall_status: overall,
  };
}

interface ControlDefinition {
  control_id: string;
  description: string;
  check: (
    contracts: ReadonlyArray<TrustContract>,
    entries: AuditEntry[],
  ) => { status: ControlStatus; evidence: string[] };
}

function evaluateControl(
  def: ControlDefinition,
  contracts: ReadonlyArray<TrustContract>,
  entries: AuditEntry[],
): ComplianceControl {
  const { status, evidence } = def.check(contracts, entries);
  return {
    control_id: def.control_id,
    description: def.description,
    status,
    evidence,
  };
}

function getControlDefinitions(framework: ComplianceFramework): ControlDefinition[] {
  switch (framework) {
    case "eu-ai-act":
      return euAiActControls();
    case "nist-ai-rmf":
      return nistAiRmfControls();
    case "iso-42001":
      return iso42001Controls();
    case "soc2":
      return soc2Controls();
    case "gdpr":
      return gdprControls();
    case "hipaa":
      return hipaaControls();
    default:
      return [];
  }
}

// ─── EU AI Act ──────────────────────────────────────────────────────

function euAiActControls(): ControlDefinition[] {
  return [
    {
      control_id: "EU-AI-ACT-Art9",
      description: "Risk management system with enforceable controls",
      check: (contracts) => {
        const hasBlockRules = contracts.some((c) => c.rules.some((r) => r.on_violation === "block"));
        return {
          status: hasBlockRules ? "satisfied" : "not_addressed",
          evidence: hasBlockRules
            ? ["Trust contracts define enforceable block-severity rules for risk mitigation"]
            : ["No blocking rules found — risk controls are not enforceable"],
        };
      },
    },
    {
      control_id: "EU-AI-ACT-Art10",
      description: "Data governance — training and validation data requirements",
      check: (contracts) => {
        const hasDataGov = contracts.some((c) => c.data_governance);
        return {
          status: hasDataGov ? "satisfied" : "not_addressed",
          evidence: hasDataGov
            ? ["Contracts declare allowed input/output data classes and retention policies"]
            : ["No data governance section found"],
        };
      },
    },
    {
      control_id: "EU-AI-ACT-Art12",
      description: "Record-keeping through automatic logging over system lifetime",
      check: (_contracts, entries) => {
        const hasEntries = entries.length > 0;
        const hasHashes = entries.every((e) => e.hash && e.prev_hash);
        return {
          status: hasEntries && hasHashes ? "satisfied" : hasEntries ? "partial" : "not_addressed",
          evidence: [
            `${entries.length} audit entries with SHA-256 hash chain`,
            hasHashes ? "All entries have tamper-evident hash links" : "Hash chain incomplete",
          ],
        };
      },
    },
    {
      control_id: "EU-AI-ACT-Art13",
      description: "Transparency — understandable documentation for deployers",
      check: (contracts) => {
        const hasDescriptions = contracts.every((c) => c.metadata.description && c.rules.every((r) => r.description));
        return {
          status: hasDescriptions ? "satisfied" : "partial",
          evidence: ["Trust contracts provide human-readable rule descriptions and metadata"],
        };
      },
    },
    {
      control_id: "EU-AI-ACT-Art14",
      description: "Human oversight measures",
      check: (contracts) => {
        const hasHumanRules = contracts.some((c) =>
          c.rules.some((r) => r.conditions.some((cond) => "field" in cond && cond.field.includes("human"))),
        );
        return {
          status: hasHumanRules ? "satisfied" : "partial",
          evidence: hasHumanRules
            ? ["Contracts include human-in-the-loop conditions"]
            : ["Consider adding human oversight conditions for high-risk decisions"],
        };
      },
    },
  ];
}

// ─── NIST AI RMF ────────────────────────────────────────────────────

function nistAiRmfControls(): ControlDefinition[] {
  return [
    {
      control_id: "NIST-GOVERN-1",
      description: "Policies and procedures documented and enforceable",
      check: (contracts) => ({
        status: contracts.length > 0 ? "satisfied" : "not_addressed",
        evidence: [`${contracts.length} trust contracts define enforceable governance policies`],
      }),
    },
    {
      control_id: "NIST-MAP-1",
      description: "Context and use case documented",
      check: (contracts) => {
        const hasMetadata = contracts.every((c) => c.metadata.description && c.metadata.stakeholders?.length);
        return {
          status: hasMetadata ? "satisfied" : "partial",
          evidence: ["Contract metadata documents scope, description, and stakeholders"],
        };
      },
    },
    {
      control_id: "NIST-MEASURE-1",
      description: "Metrics and monitoring capabilities",
      check: (_contracts, entries) => ({
        status: entries.length > 0 ? "satisfied" : "partial",
        evidence: [`${entries.length} audit entries enable measurement of violation rates and decision patterns`],
      }),
    },
    {
      control_id: "NIST-MANAGE-1",
      description: "Risk treatment through enforcement",
      check: (contracts) => {
        const severities = new Set(contracts.flatMap((c) => c.rules.map((r) => r.on_violation)));
        return {
          status: severities.has("block") ? "satisfied" : "partial",
          evidence: [`Severity levels in use: ${[...severities].join(", ")}`],
        };
      },
    },
  ];
}

// ─── ISO 42001 ──────────────────────────────────────────────────────

function iso42001Controls(): ControlDefinition[] {
  return [
    {
      control_id: "ISO42001-5.2",
      description: "AI policy defined and communicated",
      check: (contracts) => ({
        status: contracts.length > 0 ? "satisfied" : "not_addressed",
        evidence: ["Trust contracts serve as machine-enforceable AI policy documents"],
      }),
    },
    {
      control_id: "ISO42001-7.5",
      description: "Documented information controlled and versioned",
      check: (contracts) => {
        const hasVersions = contracts.every((c) => c.metadata.version);
        return {
          status: hasVersions ? "satisfied" : "partial",
          evidence: ["Contract versioning with registry supports documented information control"],
        };
      },
    },
    {
      control_id: "ISO42001-9.1",
      description: "Monitoring and measurement",
      check: (_contracts, entries) => ({
        status: entries.length > 0 ? "satisfied" : "not_addressed",
        evidence: [`${entries.length} audit entries provide continuous monitoring data`],
      }),
    },
    {
      control_id: "ISO42001-10.1",
      description: "Nonconformity tracking and corrective action",
      check: (_contracts, entries) => {
        const violations = entries.filter((e) => !e.allowed);
        return {
          status: violations.length > 0 || entries.length > 0 ? "satisfied" : "not_addressed",
          evidence: [`${violations.length} violations recorded out of ${entries.length} total decisions`],
        };
      },
    },
  ];
}

// ─── SOC 2 ──────────────────────────────────────────────────────────

function soc2Controls(): ControlDefinition[] {
  return [
    {
      control_id: "SOC2-CC6.1",
      description: "Logical access controls",
      check: (contracts) => {
        const hasRoleChecks = contracts.some((c) =>
          c.rules.some((r) => r.conditions.some((cond) => "field" in cond && cond.field.includes("roles"))),
        );
        return {
          status: hasRoleChecks ? "satisfied" : "not_addressed",
          evidence: hasRoleChecks
            ? ["Role-based conditions enforce logical access controls"]
            : ["No role-based access conditions found"],
        };
      },
    },
    {
      control_id: "SOC2-CC7.2",
      description: "System monitoring",
      check: (_contracts, entries) => ({
        status: entries.length > 0 ? "satisfied" : "not_addressed",
        evidence: [`${entries.length} decisions monitored and recorded in audit log`],
      }),
    },
    {
      control_id: "SOC2-CC7.3",
      description: "Anomaly and incident detection",
      check: (_contracts, entries) => {
        const hasHmac = entries.some((e) => e.hmac_signature);
        return {
          status: hasHmac ? "satisfied" : "partial",
          evidence: [
            "Hash chain detects tampering via SHA-256 links",
            hasHmac ? "HMAC-SHA256 signatures prevent hash recomputation attacks" : "HMAC signing not configured",
          ],
        };
      },
    },
    {
      control_id: "SOC2-CC8.1",
      description: "Change management",
      check: (contracts) => ({
        status: contracts.length > 0 ? "satisfied" : "not_addressed",
        evidence: ["Contract versioning with activation/deactivation supports change management"],
      }),
    },
  ];
}

// ─── GDPR ───────────────────────────────────────────────────────────

function gdprControls(): ControlDefinition[] {
  return [
    {
      control_id: "GDPR-Art25",
      description: "Data protection by design and default",
      check: (contracts) => {
        const hasDataGov = contracts.some((c) => c.data_governance);
        return {
          status: hasDataGov ? "satisfied" : "not_addressed",
          evidence: hasDataGov
            ? ["Data governance section enforces allowed data classes and retention"]
            : ["No data governance declarations found"],
        };
      },
    },
    {
      control_id: "GDPR-Art30",
      description: "Records of processing activities",
      check: (_contracts, entries) => ({
        status: entries.length > 0 ? "satisfied" : "not_addressed",
        evidence: [`${entries.length} processing activities recorded in tamper-evident audit log`],
      }),
    },
    {
      control_id: "GDPR-Art32",
      description: "Security of processing",
      check: (_contracts, entries) => {
        const hasHmac = entries.some((e) => e.hmac_signature);
        return {
          status: hasHmac ? "satisfied" : "partial",
          evidence: [
            "Rate limiting protects against abuse",
            hasHmac
              ? "HMAC-SHA256 audit signing ensures integrity"
              : "Configure HMAC for stronger integrity guarantees",
          ],
        };
      },
    },
  ];
}

// ─── HIPAA ──────────────────────────────────────────────────────────

function hipaaControls(): ControlDefinition[] {
  return [
    {
      control_id: "HIPAA-Privacy",
      description: "Minimum necessary PHI access controls",
      check: (contracts) => {
        const hasPhiRules = contracts.some((c) =>
          c.rules.some((r) =>
            r.conditions.some((cond) => "field" in cond && (cond.field.includes("phi") || cond.field.includes("PHI"))),
          ),
        );
        return {
          status: hasPhiRules ? "satisfied" : "not_addressed",
          evidence: hasPhiRules
            ? ["PHI-related conditions enforce minimum necessary access"]
            : ["No PHI-specific rules found"],
        };
      },
    },
    {
      control_id: "HIPAA-Security-Audit",
      description: "Audit controls — record and examine activity",
      check: (_contracts, entries) => ({
        status: entries.length > 0 ? "satisfied" : "not_addressed",
        evidence: [`${entries.length} audit entries with hash chain integrity`],
      }),
    },
    {
      control_id: "HIPAA-Security-Integrity",
      description: "Integrity controls — protect ePHI from improper alteration",
      check: (_contracts, entries) => {
        const hasHmac = entries.some((e) => e.hmac_signature);
        return {
          status: hasHmac ? "satisfied" : "partial",
          evidence: [
            "SHA-256 hash chain provides tamper evidence",
            hasHmac
              ? "HMAC signing prevents unauthorized modification"
              : "Configure HMAC for full integrity protection",
          ],
        };
      },
    },
  ];
}
