# Drop-In Threat Contracts

Pre-built trust contracts for the most common AI security threats. Each contract is copy-paste ready — load it and get instant protection.

## Quick Start

```typescript
import { GodClause } from "god-clause";
import fs from "fs";

const gov = new GodClause();
gov.loadContractYAML(fs.readFileSync("pii-redaction.contract.yaml", "utf-8"));
gov.loadContractYAML(fs.readFileSync("prompt-injection.contract.yaml", "utf-8"));
// Contracts are composable — load as many as you need
```

## Contract Catalog

| Contract | Threats | Key Action | Compliance |
|---|---|---|---|
| [**pii-redaction**](./pii-redaction.contract.yaml) | SSNs, emails, phone numbers, credit cards | Modify (redact) | GDPR, HIPAA, SOC 2 |
| [**prompt-injection**](./prompt-injection.contract.yaml) | Ignore-previous, system prompt extraction, jailbreaks | Block | NIST AI RMF, EU AI Act Art 15 |
| [**anti-hallucination**](./anti-hallucination.contract.yaml) | Low confidence, missing citations, ungrounded claims | Modify (disclaim) | EU AI Act Art 13, NIST MAP-2 |
| [**toxic-content**](./toxic-content.contract.yaml) | Toxicity, hate speech, self-harm, NSFW, violence | Block | EU AI Act Art 5, SOC 2 |
| [**cost-control**](./cost-control.contract.yaml) | Rate abuse, token blowup, expensive models | Block/Modify | SOC 2 CC6.6 |
| [**data-leakage**](./data-leakage.contract.yaml) | Internal data in outputs, cross-border violations | Block | GDPR Art 32, ISO 27001 |
| [**bias-detection**](./bias-detection.contract.yaml) | Demographic bias, protected class scoring | Block/Warn | EU AI Act Art 10, EEOC |
| [**copyright-protection**](./copyright-protection.contract.yaml) | Verbatim reproduction, missing attribution | Block/Modify | DMCA, EU Copyright Directive |
| [**mcp-tool-abuse**](./mcp-tool-abuse.contract.yaml) | Agentic tool sprawl, destructive ops, unauthorized tool calls | Block/Approve | SOC 2, NIST AI RMF, EU AI Act |

## How These Work

Each contract expects your application to set specific fields on the `output` and `input` objects. For example, `pii-redaction` expects `output.contains_pii` to be set by your PII detection pipeline.

God Clause evaluates conditions and returns a decision:
- **Block** — stop the response from reaching the user
- **Modify** — allow the response but attach obligations (redact, disclaim, truncate)
- **Warn** — allow but log a warning for monitoring

Your application handles the obligations. God Clause records every decision in a tamper-evident hash chain.

## Composing Contracts

Load multiple contracts for layered protection:

```typescript
// Load all threat contracts
const threats = ["pii-redaction", "prompt-injection", "toxic-content", "cost-control"];
for (const name of threats) {
  gov.loadContractYAML(fs.readFileSync(`examples/threats/${name}.contract.yaml`, "utf-8"));
}

// Every evaluation runs against ALL loaded contracts
const decision = await gov.evaluate(context);
```

## Customizing

Fork any contract and adjust thresholds:

```yaml
# Lower the toxicity threshold for a children's product
- id: TOX-001
  conditions:
    - field: output.toxicity_score
      operator: less_than
      value: 0.1          # Stricter than default 0.7
  on_violation: block
```

## Requirements

Each contract's header comments list what fields your application must set. No contract requires external services — they all work with the embedded library, no server needed.
