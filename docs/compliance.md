# Compliance Mapping Guide

God Clause maps directly to requirements from major AI governance frameworks. This guide shows how contract features satisfy specific regulatory controls.

## EU AI Act (Regulation 2024/1689)

The EU AI Act is the world's first comprehensive AI regulation. God Clause addresses its key technical requirements:

| Article | Requirement | God Clause Feature |
|---|---|---|
| Art. 9 | Risk management system | Trust contracts define risk controls as enforceable rules |
| Art. 10 | Data governance | `data_governance` section declares allowed data classes, retention, transfer |
| Art. 11 | Technical documentation | Contracts + audit log serve as technical documentation |
| Art. 12 | Record-keeping (automatic logging) | SHA-256 hash-chained audit log records every decision automatically |
| Art. 13 | Transparency | Plain-language summaries, human-readable YAML contracts |
| Art. 14 | Human oversight | `human_in_loop` conditions, `decide` action restrictions |
| Art. 15 | Accuracy, robustness, cybersecurity | Confidence thresholds, rate limiting, HMAC-signed audit |
| Art. 26 | Deployer obligations | Multi-tenancy enables deployer-specific contracts |

### How to demonstrate compliance

1. **Art. 12 logging**: Point auditors to `gov.getAuditEntries()` — every decision is automatically logged with hash chain integrity
2. **Art. 9 risk management**: Each trust contract IS a risk control document. The `rules` section maps risk → control → enforcement
3. **Art. 13 transparency**: Use `gov.summarize(contract)` to generate plain-language descriptions for end users

## NIST AI Risk Management Framework (AI RMF 1.0)

| NIST Function | Category | God Clause Feature |
|---|---|---|
| GOVERN | Policies and procedures | Trust contracts formalize governance policies |
| GOVERN | Roles and responsibilities | `caller.roles` conditions enforce role-based access |
| MAP | Context and use case | `metadata` section documents scope, stakeholders, effective dates |
| MAP | Risk identification | Rules with `block` severity identify and prevent high-risk behaviors |
| MEASURE | Metrics and monitoring | Audit queries enable measurement of violation rates |
| MEASURE | Evaluation | Tag-based filtering allows evaluating specific risk categories |
| MANAGE | Risk treatment | Obligations provide remediation actions (modify decisions) |
| MANAGE | Monitoring | Prometheus metrics, real-time decision tracking |

## ISO/IEC 42001 (AI Management System)

| Clause | Requirement | God Clause Feature |
|---|---|---|
| 5.2 | AI policy | Trust contracts ARE the AI policy in machine-enforceable form |
| 6.1 | Risk assessment | Rules map risks to controls with severity levels |
| 7.5 | Documented information | Contract versioning with registry, audit trail |
| 8.2 | AI risk treatment | Four severity levels (block, warn, log, modify) with obligations |
| 9.1 | Monitoring and measurement | Audit log queries, Prometheus metrics |
| 9.2 | Internal audit | Merkle seals provide cryptographic audit checkpoints |
| 10.1 | Nonconformity | Audit entries record every violation with rule_id, severity, details |

## SOC 2

| Trust Service Criteria | God Clause Feature |
|---|---|
| CC6.1 — Logical access | Role-based conditions (`caller.roles`) |
| CC6.3 — Access authorization | Tag filtering, action-level rule scoping |
| CC7.2 — Monitoring | Audit log, Prometheus metrics, webhook notifications |
| CC7.3 — Detection | Hash chain tampering detection, Merkle seal verification |
| CC8.1 — Change management | Contract versioning, activation/deactivation audit trail |
| A1.2 — Recovery | Merkle seals as integrity checkpoints, file sink with rotation |

## GDPR

| Article | Requirement | God Clause Feature |
|---|---|---|
| Art. 5(1)(f) | Integrity and confidentiality | HMAC-SHA256 audit signing, hash chain integrity |
| Art. 25 | Data protection by design | `data_governance` section enforces data class restrictions |
| Art. 30 | Records of processing | Audit log records all AI processing activities |
| Art. 32 | Security of processing | Rate limiting, role-based access, obligation enforcement |
| Art. 35 | Data protection impact assessment | Contracts document processing scope, risks, and controls |

## HIPAA

For healthcare AI, the example contract `healthcare-ai.contract.yaml` demonstrates:

| HIPAA Rule | Requirement | Contract Feature |
|---|---|---|
| Privacy Rule | Minimum necessary PHI access | `HC-001`: Block PHI in outputs |
| Privacy Rule | Access controls | `HC-005`: Clinician role required |
| Security Rule | Audit controls | Automatic hash-chained audit logging |
| Security Rule | Integrity controls | HMAC signing, Merkle seals |

## Generating Compliance Reports

```typescript
import { generateComplianceReport } from "god-clause/compliance";

const report = generateComplianceReport(gov, "eu-ai-act", {
  dateRange: { from: "2026-01-01", to: "2026-03-31" },
});

console.log(report.controls);
// [
//   { control_id: "EU-AI-ACT-Art12", status: "satisfied", evidence: [...] },
//   { control_id: "EU-AI-ACT-Art13", status: "satisfied", evidence: [...] },
//   ...
// ]
```

## Audit Evidence Package

For regulatory submissions, God Clause can produce an evidence package:

1. **Trust contracts** (YAML) — the policy documents
2. **Audit log** (JSONL) — every decision with hash chain
3. **Merkle seals** — cryptographic integrity checkpoints
4. **Compliance report** — mapped controls with evidence references
5. **Verification results** — hash chain and seal verification output

This package demonstrates to regulators that governance was not just documented, but **enforced and provably intact**.
