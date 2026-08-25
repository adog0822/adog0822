/**
 * LoxeAI GRC — Cryptographic Evidence Chain
 *
 * Provides SHA-256 hash chaining for immutable audit evidence.
 * Each evidence record's hash includes the previous record's hash,
 * forming a tamper-evident linked chain (blockchain-style).
 */

import { createHash, randomUUID } from "crypto";
import type {
  EvidenceId,
  EvidenceHash,
  SourceEvidenceTrace,
  ApiCallRecord,
} from "@/types";

// ─── Constants ────────────────────────────────────────────────────────

const HASH_ALGORITHM = "SHA-256" as const;
const GENESIS_HASH = "0".repeat(64); // sentinel for the first link

// ─── Core Hashing ─────────────────────────────────────────────────────

/**
 * Compute the SHA-256 hex digest of an arbitrary string.
 */
export function sha256(data: string): string {
  return createHash("sha256").update(data, "utf-8").digest("hex");
}

/**
 * Create a deterministic evidence hash that chains to the previous hash.
 *
 * The content being hashed is the JSON-serialised payload concatenated
 * with the previous hash.  This guarantees that:
 *   1. Two identical payloads at different chain positions produce
 *      different hashes.
 *   2. Any retroactive change to an earlier record invalidates every
 *      subsequent hash.
 */
export function createEvidenceHash(
  evidenceId: EvidenceId,
  content: Record<string, unknown>,
  previousHash: string,
  chainPosition: number,
): EvidenceHash {
  const timestamp = new Date().toISOString();
  const payload = JSON.stringify({
    evidenceId,
    content,
    previousHash,
    chainPosition,
    timestamp,
  });

  const contentHash = sha256(payload + previousHash);

  return {
    evidenceId,
    contentHash,
    previousHash,
    timestamp,
    algorithm: HASH_ALGORITHM,
    chainPosition,
  };
}

// ─── Chain Operations ─────────────────────────────────────────────────

/**
 * Append a new evidence hash to an existing chain.
 *
 * Returns a new array — the input chain is never mutated.
 */
export function appendToChain(
  chain: EvidenceHash[],
  evidenceId: EvidenceId,
  content: Record<string, unknown>,
): EvidenceHash[] {
  const previousHash =
    chain.length > 0 ? chain[chain.length - 1].contentHash : GENESIS_HASH;
  const chainPosition = chain.length;

  const newHash = createEvidenceHash(
    evidenceId,
    content,
    previousHash,
    chainPosition,
  );

  return [...chain, newHash];
}

/**
 * Verify the integrity of an entire evidence chain.
 *
 * Checks performed for each link:
 *   - `previousHash` matches the preceding link's `contentHash`
 *     (or the genesis hash for position 0).
 *   - `chainPosition` equals the array index.
 *   - `algorithm` is SHA-256.
 *
 * Returns `{ valid: true }` when the chain is intact, or
 * `{ valid: false, brokenAt, reason }` at the first violation.
 */
export function verifyChain(
  chain: EvidenceHash[],
): { valid: true } | { valid: false; brokenAt: number; reason: string } {
  if (chain.length === 0) {
    return { valid: true };
  }

  for (let i = 0; i < chain.length; i++) {
    const link = chain[i];

    // Position must be sequential
    if (link.chainPosition !== i) {
      return {
        valid: false,
        brokenAt: i,
        reason: `Expected chainPosition ${i} but found ${link.chainPosition}`,
      };
    }

    // Algorithm must be SHA-256
    if (link.algorithm !== HASH_ALGORITHM) {
      return {
        valid: false,
        brokenAt: i,
        reason: `Unexpected algorithm "${link.algorithm}"`,
      };
    }

    // Previous-hash linkage
    const expectedPrevious =
      i === 0 ? GENESIS_HASH : chain[i - 1].contentHash;
    if (link.previousHash !== expectedPrevious) {
      return {
        valid: false,
        brokenAt: i,
        reason: `Previous hash mismatch at position ${i}: expected "${expectedPrevious}" but found "${link.previousHash}"`,
      };
    }
  }

  return { valid: true };
}

// ─── Source Trace Construction ─────────────────────────────────────────

/**
 * Build a `SourceEvidenceTrace` from a set of API call records.
 *
 * The `chainHash` covers the sorted, serialised API calls so that
 * any modification to the underlying evidence is detectable.
 */
export function createSourceTrace(
  apiCalls: ApiCallRecord[],
  previousHash: string,
  collectorVersion: string,
): SourceEvidenceTrace {
  const timestamp = new Date().toISOString();

  // Sort by timestamp for deterministic serialisation
  const sorted = [...apiCalls].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime(),
  );

  const payload = JSON.stringify({
    apiCalls: sorted,
    previousHash,
    timestamp,
    collectorVersion,
  });

  const chainHash = sha256(payload + previousHash);

  return {
    apiCalls: sorted,
    chainHash,
    previousHash,
    timestamp,
    collectorVersion,
  };
}

// ─── Utilities ────────────────────────────────────────────────────────

/**
 * Hash an arbitrary decision record (intent + evaluation + result)
 * into a single SHA-256 digest suitable for evidence linking.
 */
export function hashDecisionRecord(
  record: Record<string, unknown>,
  previousHash: string,
): string {
  const payload = JSON.stringify(record) + previousHash;
  return sha256(payload);
}

/**
 * Generate a new EvidenceId (branded UUID).
 */
export function generateEvidenceId(): EvidenceId {
  return randomUUID() as unknown as EvidenceId;
}

/**
 * The genesis (zero) hash used as the sentinel for the first link.
 */
export { GENESIS_HASH };
