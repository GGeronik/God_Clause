# Audit Trail: What Each Layer Proves

A plain database log can be edited by anyone with write access and leaves no trace. God Clause's audit log makes edits detectable. This page states what each layer proves and what it does not.

## The Problem With Database Logs

When an auditor asks "prove this AI decision happened exactly as recorded," a database log has a fundamental weakness: **anyone with database access can silently edit, delete, or reorder entries.** There is no way to prove the log hasn't been modified after the fact.

A DBA, a compromised credential, or a buggy migration can alter such a log without any trace.

## God Clause's Four Layers

### Layer 1: SHA-256 Hash Chain

Every audit entry contains a `hash` field — a SHA-256 digest of all the entry's fields (sorted keys, deterministic JSON). Crucially, each entry also contains `prev_hash` — the hash of the previous entry.

```
Entry 1                Entry 2                Entry 3
┌──────────────┐      ┌──────────────┐      ┌──────────────┐
│ prev_hash: 0 │      │ prev_hash:   │      │ prev_hash:   │
│ ...fields... │──────│  hash(E1)    │──────│  hash(E2)    │
│ hash: H1     │      │ ...fields... │      │ ...fields... │
└──────────────┘      │ hash: H2     │      │ hash: H3     │
                      └──────────────┘      └──────────────┘
```

**What this proves**: If anyone modifies, deletes, or reorders any entry, the chain breaks. The hash of the modified entry won't match what the next entry expects in `prev_hash`. Tampering is mathematically detectable.

**Verification**: `gov.verifyAuditChain()` walks the entire chain and reports the exact index where tampering is detected.

### Layer 2: HMAC-SHA256 Signing

Hash chains have a weakness: an attacker who modifies an entry could recompute all subsequent hashes to make the chain look valid again.

HMAC signing fixes this. When an `auditSecretKey` is configured, every entry gets an `hmac_signature` — an HMAC-SHA256 computed with the secret key. Without the key, recomputing valid signatures is computationally infeasible.

```typescript
const gov = new GodClause({ auditSecretKey: "your-secret-key" });
// Now every audit entry has an hmac_signature field
```

**What this proves**: Even a fully compromised database cannot produce valid audit entries without the signing key. Separate the key from the database and you get true non-repudiation.

### Layer 3: Merkle Seal Checkpoints

Verifying a chain of 10 million entries is slow. Merkle seals create periodic snapshots.

```
Entries [E1, E2, E3, E4] → Hashes [H1, H2, H3, H4]

        Merkle Root
        /          \
    H(H1+H2)    H(H3+H4)
     /    \       /    \
    H1    H2    H3    H4
```

A seal stores the `merkle_root`, the entry range, and the entry count. Later, you can verify any segment by recomputing the Merkle root from current entries and comparing. O(log n) verification.

```typescript
const seal = gov.sealAuditChain();
// seal.merkle_root = cryptographic snapshot of all entries since last seal
```

**What this proves**: Integrity of an entire audit segment in a single hash comparison.

### Layer 4: DSSE Contract Signatures

Dead Simple Signing Envelopes (DSSE) sign the trust contracts themselves.

```typescript
import { signContract, verifyContractSignature } from "god-clause";

const envelope = signContract(contract, {
  privateKey: signingKey,
  keyId: "policy-team-key-2025",
});
// envelope contains base64 payload + Ed25519/ECDSA signature
```

**What this proves**: WHO authored or approved each policy contract. The signature is bound to the exact YAML content — any modification invalidates it.

## The Complete Chain

When asked "show that your AI system followed its policy on March 15th":

1. **DSSE envelope** shows who signed the policy contract
2. **Audit hash chain** shows every decision was recorded in sequence and none was altered since
3. **HMAC signatures** show entries weren't recomputed by someone without the key
4. **Merkle seal** checks the integrity of a whole audit segment in one comparison
5. **`governance_context.policy_sha256`** in each audit entry ties it to the exact policy version that produced it

## What It Does Not Prove

- **When.** Entry and seal timestamps come from the host clock. Nothing anchors them to an external time source.
- **What the application did.** The log records the decision and its obligations, not whether the host applied them.
- **Anything, if the HMAC key sits next to the log.** The HMAC layer only helps when the key is held separately from whoever can write to the log.
- **Compliance.** God Clause generates no compliance reports and certifies nothing against any framework. The mapping below is a pointer to which control each layer is relevant to, not a claim of satisfying it.

## Compliance Mapping

| Evidence Layer | SOC 2 | EU AI Act | GDPR | HIPAA | NIST AI RMF |
|---|---|---|---|---|---|
| Hash chain | CC6.1 Integrity | Art 12 Logging | Art 30 Records | 164.312(b) Audit | GOVERN-1 |
| HMAC signing | CC6.1 Integrity | Art 15 Accuracy | Art 32 Security | 164.312(c) Integrity | MANAGE-2 |
| Merkle seals | CC7.2 Monitoring | Art 12 Logging | Art 5(1)(f) Integrity | 164.312(c) Integrity | MANAGE-3 |
| DSSE signatures | CC6.3 Authorization | Art 13 Transparency | Art 24 Responsibility | 164.312(d) Auth | MAP-1 |
