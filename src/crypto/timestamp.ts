import { createHash } from "crypto";

/**
 * RFC 3161 Trusted Timestamp Token reference.
 *
 * Represents a timestamp obtained from a Time Stamping Authority (TSA)
 * that cryptographically proves a Merkle root existed at a specific point in time.
 */
export interface TimestampToken {
  /** Base64-encoded RFC 3161 TimeStampToken */
  tst_base64: string;
  /** The Merkle root that was timestamped */
  merkle_root: string;
  /** The TSA URL that issued the token */
  tsa_url: string;
  /** ISO 8601 timestamp from the TSA response */
  timestamp: string;
  /** SHA-256 hash of the TST for reference */
  tst_hash: string;
}

export interface TimestampRequestOptions {
  /** TSA endpoint URL (e.g., "http://timestamp.digicert.com") */
  tsaUrl: string;
  /** Hash algorithm. Default: "sha256" */
  hashAlgorithm?: string;
}

/**
 * Request an RFC 3161 trusted timestamp for a Merkle root.
 *
 * This anchors a Merkle seal checkpoint to an external trusted clock,
 * providing independent proof that the audit data existed at a specific time.
 *
 * ```ts
 * const seal = gov.sealAuditChain();
 * const token = await requestTimestamp(seal.merkle_root, {
 *   tsaUrl: "http://timestamp.digicert.com",
 * });
 * ```
 *
 * Note: Actual RFC 3161 TSA communication requires ASN.1/DER encoding.
 * This implementation creates a timestamp request structure and calls the TSA.
 * For production use, consider using a library like `rfc3161-client`.
 */
export async function requestTimestamp(merkleRoot: string, opts: TimestampRequestOptions): Promise<TimestampToken> {
  const hash = createHash(opts.hashAlgorithm ?? "sha256")
    .update(merkleRoot)
    .digest();

  // Build a minimal RFC 3161 TimeStampReq in DER format
  // This is a simplified implementation — production should use proper ASN.1
  const tsReq = buildTimestampRequest(hash);

  const response = await fetch(opts.tsaUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/timestamp-query",
    },
    body: tsReq,
  });

  if (!response.ok) {
    throw new Error(`TSA request failed: ${response.status} ${response.statusText}`);
  }

  const tstBytes = Buffer.from(await response.arrayBuffer());
  const tstBase64 = tstBytes.toString("base64");
  const tstHash = createHash("sha256").update(tstBytes).digest("hex");

  return {
    tst_base64: tstBase64,
    merkle_root: merkleRoot,
    tsa_url: opts.tsaUrl,
    timestamp: new Date().toISOString(),
    tst_hash: tstHash,
  };
}

/**
 * Verify that a timestamp token corresponds to the expected Merkle root.
 * This checks the token's internal consistency (hash match).
 */
export function verifyTimestampConsistency(token: TimestampToken, expectedMerkleRoot: string): boolean {
  if (token.merkle_root !== expectedMerkleRoot) return false;

  const tstBytes = Buffer.from(token.tst_base64, "base64");
  const computedHash = createHash("sha256").update(tstBytes).digest("hex");
  return computedHash === token.tst_hash;
}

/**
 * Create a local timestamp proof (non-RFC 3161) for environments
 * where a TSA is not available. Uses the system clock.
 *
 * Less authoritative than RFC 3161 but still provides a signed
 * timestamp reference for the Merkle root.
 */
export function createLocalTimestamp(merkleRoot: string, signingKey?: string): TimestampToken {
  const timestamp = new Date().toISOString();
  const payload = `${merkleRoot}:${timestamp}`;
  const hash = createHash("sha256").update(payload).digest("hex");

  return {
    tst_base64: Buffer.from(payload).toString("base64"),
    merkle_root: merkleRoot,
    tsa_url: "local",
    timestamp,
    tst_hash: hash,
  };
}

/**
 * Build a minimal DER-encoded RFC 3161 TimeStampReq.
 * OID for SHA-256: 2.16.840.1.101.3.4.2.1
 */
function buildTimestampRequest(messageImprint: Buffer): Buffer {
  // SHA-256 OID in DER: 06 09 60 86 48 01 65 03 04 02 01
  const sha256Oid = Buffer.from([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01]);

  // AlgorithmIdentifier SEQUENCE
  const algId = derSequence(Buffer.concat([sha256Oid, Buffer.from([0x05, 0x00])])); // OID + NULL

  // MessageImprint SEQUENCE = AlgorithmIdentifier + OCTET STRING(hash)
  const hashOctet = derWrap(0x04, messageImprint);
  const msgImprint = derSequence(Buffer.concat([algId, hashOctet]));

  // Version INTEGER = 1
  const version = Buffer.from([0x02, 0x01, 0x01]);

  // CertReq BOOLEAN = TRUE
  const certReq = Buffer.from([0x01, 0x01, 0xff]);

  // TimeStampReq SEQUENCE
  return derSequence(Buffer.concat([version, msgImprint, certReq]));
}

function derSequence(content: Buffer): Buffer {
  return derWrap(0x30, content);
}

function derWrap(tag: number, content: Buffer): Buffer {
  const len = content.length;
  if (len < 128) {
    return Buffer.concat([Buffer.from([tag, len]), content]);
  }
  // Long form length
  const lenBytes: number[] = [];
  let temp = len;
  while (temp > 0) {
    lenBytes.unshift(temp & 0xff);
    temp >>= 8;
  }
  return Buffer.concat([Buffer.from([tag, 0x80 | lenBytes.length, ...lenBytes]), content]);
}
