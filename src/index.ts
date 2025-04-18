/**
 * Triple Ratchet - Main exports
 */

// Re-export types and constants
export * from "./types";
export * from "./constants";

// Environment detection (Web Crypto)
export { getCrypto } from "./utils/environment";

// Buffer utilities
export {
  concatBuffers,
  equalBuffers,
  stringToBytes,
  bytesToString,
} from "./utils/buffer";

// Crypto utilities
export {
  generateECDHKeyPair,
  generateSigningKeyPair,
  computeDH,
  hkdfDerive,
  importHmacKey,
  importAesKey,
  encryptAES,
  decryptAES,
  exportRawKey,
  equalPublicKeys,
  verifySignature,
  serializePublicKey,
  deserializePublicKey,
  hashData,
  signData,
} from "./crypto/crypto-utils";

// Ratchet protocol functions
export {
  createIdentityState,
  createPreKeyBundle,
  initializeRatchetInitiator,
  initializeRatchetReceiver,
  ratchetEncrypt,
  ratchetDecrypt,
} from "./protocol/ratchet-logic";
