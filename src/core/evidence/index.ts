/**
 * Cryptographic Evidence Pipeline
 *
 * Every action hashed, timestamped, and chained into an immutable audit ledger.
 * SHA-256 hash chains with blockchain-style linked hashes.
 */
export {
  createEvidenceHash,
  verifyChain,
  appendToChain,
  createSourceTrace,
} from "./crypto-chain.js";
