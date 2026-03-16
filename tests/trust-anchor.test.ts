import { describe, it, expect, beforeEach } from "vitest";
import { randomBytes } from "crypto";
import {
  SoftwareTrustAnchor,
  TPMTrustAnchor,
  SGXTrustAnchor,
  FirecrackerTrustAnchor,
  NotImplementedError,
  createTrustAnchor,
} from "../src/attestation/trust-anchor";

describe("SoftwareTrustAnchor", () => {
  let anchor: SoftwareTrustAnchor;

  beforeEach(async () => {
    anchor = new SoftwareTrustAnchor();
    await anchor.initialize();
  });

  it("reports type as 'software'", () => {
    expect(anchor.type).toBe("software");
  });

  it("is always available", async () => {
    expect(await anchor.isAvailable()).toBe(true);
  });

  it("throws if used before initialization", async () => {
    const uninit = new SoftwareTrustAnchor();
    await expect(uninit.getPublicKey()).rejects.toThrow("not initialized");
  });

  it("returns a hex-encoded public key", async () => {
    const pk = await anchor.getPublicKey();
    expect(typeof pk).toBe("string");
    expect(pk.length).toBeGreaterThan(0);
    // Verify it's valid hex
    expect(/^[0-9a-f]+$/i.test(pk)).toBe(true);
  });

  it("sign and verify round-trip", async () => {
    const data = Buffer.from("hello world");
    const signature = await anchor.sign(data);
    expect(signature).toBeInstanceOf(Buffer);
    expect(signature.length).toBeGreaterThan(0);

    const valid = await anchor.verify(data, signature);
    expect(valid).toBe(true);
  });

  it("verify rejects tampered data", async () => {
    const data = Buffer.from("original");
    const signature = await anchor.sign(data);
    const tampered = Buffer.from("tampered");
    const valid = await anchor.verify(tampered, signature);
    expect(valid).toBe(false);
  });

  it("verify rejects tampered signature", async () => {
    const data = Buffer.from("test");
    const signature = await anchor.sign(data);
    signature[0] ^= 0xff; // flip a byte
    const valid = await anchor.verify(data, signature);
    expect(valid).toBe(false);
  });

  it("seal and unseal round-trip", async () => {
    const plaintext = Buffer.from("sensitive data for sealing");
    const sealed = await anchor.sealData(plaintext);
    expect(sealed).toBeInstanceOf(Buffer);
    expect(sealed.length).toBeGreaterThan(plaintext.length); // IV + authTag + encrypted

    const unsealed = await anchor.unsealData(sealed);
    expect(unsealed).toEqual(plaintext);
  });

  it("unseal rejects tampered sealed data", async () => {
    const plaintext = Buffer.from("important data");
    const sealed = await anchor.sealData(plaintext);
    sealed[sealed.length - 1] ^= 0xff; // tamper with ciphertext
    await expect(anchor.unsealData(sealed)).rejects.toThrow();
  });

  it("unseal rejects truncated data", async () => {
    const tooShort = Buffer.alloc(10);
    await expect(anchor.unsealData(tooShort)).rejects.toThrow("too short");
  });

  it("generates a valid quote", async () => {
    const nonce = randomBytes(32);
    const quote = await anchor.quote(nonce);

    expect(quote.anchorType).toBe("software");
    expect(quote.nonce).toBe(nonce.toString("hex"));
    expect(quote.publicKey).toBe(await anchor.getPublicKey());
    expect(Object.keys(quote.measurements)).toContain("node_version");
    expect(Object.keys(quote.measurements)).toContain("platform");
    expect(typeof quote.signature).toBe("string");
    expect(typeof quote.timestamp).toBe("string");
  });

  it("quote signature is verifiable", async () => {
    const nonce = randomBytes(32);
    const quote = await anchor.quote(nonce);

    // Reconstruct payload and verify signature
    const payload = Buffer.from(JSON.stringify({
      nonce: quote.nonce,
      measurements: quote.measurements,
      timestamp: quote.timestamp,
    }));

    const sigBuf = Buffer.from(quote.signature, "hex");
    const valid = await anchor.verify(payload, sigBuf);
    expect(valid).toBe(true);
  });

  it("getInfo returns correct capabilities", () => {
    const info = anchor.getInfo();
    expect(info.type).toBe("software");
    expect(info.available).toBe(true);
    expect(info.capabilities).toContain("sign");
    expect(info.capabilities).toContain("verify");
    expect(info.capabilities).toContain("quote");
    expect(info.capabilities).toContain("seal");
    expect(info.capabilities).toContain("unseal");
  });
});

describe("TPMTrustAnchor", () => {
  it("reports type as 'tpm'", () => {
    const anchor = new TPMTrustAnchor();
    expect(anchor.type).toBe("tpm");
  });

  it("falls back to software when TPM unavailable", async () => {
    const anchor = new TPMTrustAnchor();
    await anchor.initialize(); // Should not throw - falls back

    // Should be able to sign (via fallback)
    const data = Buffer.from("test");
    const signature = await anchor.sign(data);
    expect(signature).toBeInstanceOf(Buffer);

    const valid = await anchor.verify(data, signature);
    expect(valid).toBe(true);
  });

  it("fallback quote has 'tpm-fallback' anchor type", async () => {
    const anchor = new TPMTrustAnchor();
    await anchor.initialize();

    const nonce = randomBytes(32);
    const quote = await anchor.quote(nonce);
    expect(quote.anchorType).toBe("tpm-fallback");
  });

  it("fallback seal/unseal works", async () => {
    const anchor = new TPMTrustAnchor();
    await anchor.initialize();

    const data = Buffer.from("sealed via tpm fallback");
    const sealed = await anchor.sealData(data);
    const unsealed = await anchor.unsealData(sealed);
    expect(unsealed).toEqual(data);
  });
});

describe("SGXTrustAnchor", () => {
  it("reports not available", async () => {
    const anchor = new SGXTrustAnchor();
    expect(await anchor.isAvailable()).toBe(false);
  });

  it("throws NotImplementedError on all operations", async () => {
    const anchor = new SGXTrustAnchor();
    await expect(anchor.initialize()).rejects.toThrow(NotImplementedError);
    await expect(anchor.getPublicKey()).rejects.toThrow(NotImplementedError);
    await expect(anchor.sign(Buffer.from("x"))).rejects.toThrow(NotImplementedError);
    await expect(anchor.verify(Buffer.from("x"), Buffer.from("y"))).rejects.toThrow(NotImplementedError);
    await expect(anchor.quote(Buffer.from("n"))).rejects.toThrow(NotImplementedError);
    await expect(anchor.sealData(Buffer.from("d"))).rejects.toThrow(NotImplementedError);
    await expect(anchor.unsealData(Buffer.from("s"))).rejects.toThrow(NotImplementedError);
  });

  it("getInfo shows empty capabilities", () => {
    const anchor = new SGXTrustAnchor();
    const info = anchor.getInfo();
    expect(info.available).toBe(false);
    expect(info.capabilities).toEqual([]);
  });
});

describe("FirecrackerTrustAnchor", () => {
  it("reports not available", async () => {
    const anchor = new FirecrackerTrustAnchor();
    expect(await anchor.isAvailable()).toBe(false);
  });

  it("throws NotImplementedError on initialize", async () => {
    const anchor = new FirecrackerTrustAnchor();
    await expect(anchor.initialize()).rejects.toThrow(NotImplementedError);
  });

  it("getInfo shows empty capabilities", () => {
    const anchor = new FirecrackerTrustAnchor();
    const info = anchor.getInfo();
    expect(info.type).toBe("firecracker");
    expect(info.available).toBe(false);
    expect(info.capabilities).toEqual([]);
  });
});

describe("createTrustAnchor factory", () => {
  it("returns software anchor when no hardware available", async () => {
    const anchor = await createTrustAnchor(["software"]);
    expect(anchor.type).toBe("software");

    // Should be initialized and usable
    const pk = await anchor.getPublicKey();
    expect(pk.length).toBeGreaterThan(0);
  });

  it("defaults to software when tpm is unavailable", async () => {
    const anchor = await createTrustAnchor(); // default: ["tpm", "software"]
    // TPM is not available in CI/test, so should fall back to software or tpm-fallback
    expect(["software", "tpm"].includes(anchor.type)).toBe(true);
  });

  it("skips unknown anchor types", async () => {
    const anchor = await createTrustAnchor(["nonexistent", "software"]);
    expect(anchor.type).toBe("software");
  });

  it("falls back to software even with empty preference list", async () => {
    const anchor = await createTrustAnchor([]);
    expect(anchor.type).toBe("software");
  });
});
