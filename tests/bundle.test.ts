import { describe, it, expect, vi, afterEach } from "vitest";
import { generateKeyPairSync } from "crypto";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";
import type { TrustContract } from "../src/types";
import {
  packBundle,
  signBundle,
  verifyBundle,
  unpackBundle,
  BundleWatcher,
} from "../src/contracts/bundle";

// ─── Test key pair (RSA 2048) ────────────────────────────────────────

const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// A second key pair for "wrong key" tests
const { publicKey: wrongPublicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// ─── Helper: minimal valid TrustContract ─────────────────────────────

function makeContract(name = "test-contract"): TrustContract {
  return {
    schema_version: "1.0",
    metadata: {
      name,
      version: "1.0.0",
      author: "Test Author",
      description: "A test contract",
      effective_date: "2025-01-01",
    },
    data_governance: {
      allowed_input_classes: ["public"],
      allowed_output_classes: ["public"],
      retention_period: "P30D",
      cross_border_transfer: false,
    },
    rules: [
      {
        id: "R-001",
        description: "Allow generate when output.ok is true",
        action: "generate",
        conditions: [
          { field: "output.ok", operator: "equals", value: true },
        ],
        on_violation: "block",
      },
    ],
  };
}

// ─── packBundle ──────────────────────────────────────────────────────

describe("packBundle", () => {
  it("creates a bundle with correct format_version and bundle_id", () => {
    const bundle = packBundle([makeContract()]);
    expect(bundle.format_version).toBe("1.0");
    expect(bundle.bundle_id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(bundle.created_at).toBeTruthy();
  });

  it("computes contract fingerprints", () => {
    const contracts = [makeContract("a"), makeContract("b")];
    const bundle = packBundle(contracts);
    expect(bundle.metadata.contract_fingerprints).toHaveLength(2);
    // Fingerprints should be hex SHA-256 hashes (64 chars)
    for (const fp of bundle.metadata.contract_fingerprints) {
      expect(fp).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("includes all contracts", () => {
    const contracts = [makeContract("x"), makeContract("y"), makeContract("z")];
    const bundle = packBundle(contracts, { author: "me", description: "test" });
    expect(bundle.contracts).toHaveLength(3);
    expect(bundle.metadata.author).toBe("me");
    expect(bundle.metadata.description).toBe("test");
  });
});

// ─── signBundle ──────────────────────────────────────────────────────

describe("signBundle", () => {
  it("produces a SignedBundle with a DSSE envelope", () => {
    const bundle = packBundle([makeContract()]);
    const signed = signBundle(bundle, { privateKey, keyId: "key-1" });

    expect(signed.envelope).toBeDefined();
    expect(signed.envelope.payloadType).toBe("application/vnd.godclause.bundle+json");
    expect(signed.envelope.payload).toBeTruthy();
    expect(signed.envelope.signatures).toHaveLength(1);
    expect(signed.envelope.signatures[0].keyid).toBe("key-1");
    expect(signed.envelope.signatures[0].sig).toBeTruthy();
  });
});

// ─── verifyBundle ────────────────────────────────────────────────────

describe("verifyBundle", () => {
  it("returns valid=true for a correctly signed bundle", () => {
    const bundle = packBundle([makeContract()]);
    const signed = signBundle(bundle, { privateKey, keyId: "key-1" });
    const result = verifyBundle(signed, { publicKey });

    expect(result.valid).toBe(true);
    expect(result.bundle).toBeDefined();
    expect(result.bundle!.bundle_id).toBe(bundle.bundle_id);
  });

  it("returns valid=false for a tampered payload", () => {
    const bundle = packBundle([makeContract()]);
    const signed = signBundle(bundle, { privateKey, keyId: "key-1" });

    // Tamper with the payload
    const decoded = JSON.parse(
      Buffer.from(signed.envelope.payload, "base64").toString("utf-8"),
    );
    decoded.bundle_id = "tampered-id";
    signed.envelope.payload = Buffer.from(JSON.stringify(decoded)).toString("base64");

    const result = verifyBundle(signed, { publicKey });
    expect(result.valid).toBe(false);
  });

  it("returns valid=false for wrong public key", () => {
    const bundle = packBundle([makeContract()]);
    const signed = signBundle(bundle, { privateKey, keyId: "key-1" });
    const result = verifyBundle(signed, { publicKey: wrongPublicKey });

    expect(result.valid).toBe(false);
  });
});

// ─── unpackBundle ────────────────────────────────────────────────────

describe("unpackBundle", () => {
  it("returns contracts array on valid signature", () => {
    const contracts = [makeContract("a"), makeContract("b")];
    const bundle = packBundle(contracts);
    const signed = signBundle(bundle, { privateKey, keyId: "key-1" });
    const result = unpackBundle(signed, { publicKey });

    expect(result).toHaveLength(2);
    expect(result[0].metadata.name).toBe("a");
    expect(result[1].metadata.name).toBe("b");
  });

  it("throws on invalid signature", () => {
    const bundle = packBundle([makeContract()]);
    const signed = signBundle(bundle, { privateKey, keyId: "key-1" });

    expect(() => unpackBundle(signed, { publicKey: wrongPublicKey })).toThrow(
      "Bundle signature verification failed",
    );
  });
});

// ─── Round-trip ──────────────────────────────────────────────────────

describe("round-trip", () => {
  it("pack → sign → verify → unpack preserves contracts", () => {
    const contracts = [makeContract("alpha"), makeContract("beta")];
    const bundle = packBundle(contracts);
    const signed = signBundle(bundle, { privateKey, keyId: "round-trip-key" });
    const verifyResult = verifyBundle(signed, { publicKey });

    expect(verifyResult.valid).toBe(true);
    expect(verifyResult.bundle!.contracts).toHaveLength(2);

    const unpacked = unpackBundle(signed, { publicKey });
    expect(unpacked).toHaveLength(2);
    expect(unpacked[0].metadata.name).toBe("alpha");
    expect(unpacked[1].metadata.name).toBe("beta");
    expect(unpacked[0].rules).toHaveLength(1);
  });
});

// ─── BundleWatcher ───────────────────────────────────────────────────

describe("BundleWatcher", () => {
  let tmpDir: string;

  afterEach(() => {
    if (tmpDir) {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  function writeSignedBundle(contracts: TrustContract[]): string {
    tmpDir = mkdtempSync(join(tmpdir(), "bundle-watcher-"));
    const bundle = packBundle(contracts);
    const signed = signBundle(bundle, { privateKey, keyId: "watcher-key" });
    const filePath = join(tmpDir, "bundle.json");
    writeFileSync(filePath, JSON.stringify(signed), "utf-8");
    return filePath;
  }

  it("loads contracts from a file source", async () => {
    const contracts = [makeContract("watched-contract")];
    const filePath = writeSignedBundle(contracts);

    const loaded: TrustContract[] = [];
    const watcher = new BundleWatcher({
      source: filePath,
      publicKey,
      pollIntervalMs: 100_000, // won't fire during test
      onReload: (c) => loaded.push(...c),
    });

    watcher.start();
    // Allow the immediate poll to complete
    await new Promise((r) => setTimeout(r, 50));
    watcher.stop();

    expect(loaded).toHaveLength(1);
    expect(loaded[0].metadata.name).toBe("watched-contract");
  });

  it("skips reload when bundle_id is unchanged", async () => {
    const contracts = [makeContract("same-bundle")];
    const filePath = writeSignedBundle(contracts);

    let reloadCount = 0;
    const watcher = new BundleWatcher({
      source: filePath,
      publicKey,
      pollIntervalMs: 30, // fast poll
      onReload: () => {
        reloadCount++;
      },
    });

    watcher.start();
    // Wait for several poll cycles
    await new Promise((r) => setTimeout(r, 150));
    watcher.stop();

    // Should have loaded exactly once despite multiple polls
    expect(reloadCount).toBe(1);
  });

  it("calls onError on verification failure", async () => {
    // Write a bundle signed with the real key
    const contracts = [makeContract("bad-bundle")];
    tmpDir = mkdtempSync(join(tmpdir(), "bundle-watcher-err-"));
    const bundle = packBundle(contracts);
    const signed = signBundle(bundle, { privateKey, keyId: "k" });
    const filePath = join(tmpDir, "bundle.json");
    writeFileSync(filePath, JSON.stringify(signed), "utf-8");

    const errors: Error[] = [];
    const watcher = new BundleWatcher({
      source: filePath,
      publicKey: wrongPublicKey, // wrong key — verification will fail
      pollIntervalMs: 100_000,
      onError: (err) => errors.push(err),
    });

    watcher.start();
    await new Promise((r) => setTimeout(r, 50));
    watcher.stop();

    expect(errors).toHaveLength(1);
    expect(errors[0].message).toContain("verification failed");
  });
});
