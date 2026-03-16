import { describe, it, expect } from "vitest";
import { generateKeyPairSync } from "crypto";
import { signContract, verifyContractSignature, contractFingerprint } from "../src/crypto/dsse";
import { createLocalTimestamp, verifyTimestampConsistency } from "../src/crypto/timestamp";
import { parseContract } from "../src/contracts/parser";

const CONTRACT_YAML = `
schema_version: "1.0"
metadata:
  name: Crypto Test
  version: "1.0.0"
  author: Test
  description: Contract for crypto tests
  effective_date: "2025-01-01"
data_governance:
  allowed_input_classes: [public]
  allowed_output_classes: [public]
  retention_period: P30D
  cross_border_transfer: false
rules:
  - id: R-001
    description: Always allow
    action: generate
    conditions:
      - field: output.ok
        operator: equals
        value: true
    on_violation: block
    tags: [test]
`;

describe("DSSE Contract Signing", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const contract = parseContract(CONTRACT_YAML);

  it("signs a contract and produces a valid envelope", () => {
    const envelope = signContract(contract, {
      privateKey,
      keyId: "test-key-1",
    });

    expect(envelope.payloadType).toBe("application/vnd.godclause.contract+yaml");
    expect(envelope.payload).toBeTruthy();
    expect(envelope.signatures).toHaveLength(1);
    expect(envelope.signatures[0].keyid).toBe("test-key-1");
    expect(envelope.signatures[0].sig).toBeTruthy();
  });

  it("verifies a valid signature", () => {
    const envelope = signContract(contract, {
      privateKey,
      keyId: "test-key-1",
    });

    const result = verifyContractSignature(envelope, { publicKey });

    expect(result.valid).toBe(true);
    expect(result.keyId).toBe("test-key-1");
    expect(result.contract.metadata.name).toBe("Crypto Test");
  });

  it("rejects a tampered payload", () => {
    const envelope = signContract(contract, {
      privateKey,
      keyId: "test-key-1",
    });

    // Tamper with the payload
    const tampered = { ...envelope, payload: Buffer.from("tampered").toString("base64") };
    const result = verifyContractSignature(tampered, { publicKey });

    expect(result.valid).toBe(false);
  });

  it("rejects a wrong public key", () => {
    const otherKey = generateKeyPairSync("ec", {
      namedCurve: "P-256",
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });

    const envelope = signContract(contract, {
      privateKey,
      keyId: "test-key-1",
    });

    const result = verifyContractSignature(envelope, { publicKey: otherKey.publicKey });
    expect(result.valid).toBe(false);
  });

  it("round-trips contract data through sign/verify", () => {
    const envelope = signContract(contract, {
      privateKey,
      keyId: "key-2026",
    });

    const { valid, contract: recovered } = verifyContractSignature(envelope, { publicKey });
    expect(valid).toBe(true);
    expect(recovered.metadata.version).toBe("1.0.0");
    expect(recovered.rules).toHaveLength(1);
    expect(recovered.rules[0].id).toBe("R-001");
  });
});

describe("Contract Fingerprint", () => {
  it("produces consistent fingerprints", () => {
    const contract = parseContract(CONTRACT_YAML);
    const fp1 = contractFingerprint(contract);
    const fp2 = contractFingerprint(contract);

    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(64); // SHA-256 hex
  });

  it("produces different fingerprints for different contracts", () => {
    const contract1 = parseContract(CONTRACT_YAML);
    const contract2 = parseContract(CONTRACT_YAML.replace("Crypto Test", "Different Name"));

    expect(contractFingerprint(contract1)).not.toBe(contractFingerprint(contract2));
  });
});

describe("Local Timestamps", () => {
  it("creates a local timestamp token", () => {
    const token = createLocalTimestamp("abc123merkleroot");

    expect(token.merkle_root).toBe("abc123merkleroot");
    expect(token.tsa_url).toBe("local");
    expect(token.tst_base64).toBeTruthy();
    expect(token.tst_hash).toHaveLength(64);
    expect(token.timestamp).toBeTruthy();
  });

  it("verifies timestamp consistency", () => {
    const token = createLocalTimestamp("merkle-root-hash");
    expect(verifyTimestampConsistency(token, "merkle-root-hash")).toBe(true);
  });

  it("rejects mismatched merkle root", () => {
    const token = createLocalTimestamp("original-root");
    expect(verifyTimestampConsistency(token, "different-root")).toBe(false);
  });

  it("rejects tampered tst_hash", () => {
    const token = createLocalTimestamp("merkle-root");
    const tampered = { ...token, tst_hash: "0".repeat(64) };
    expect(verifyTimestampConsistency(tampered, "merkle-root")).toBe(false);
  });
});
