// === File: src/constants.ts ===

import { p256 } from "@noble/curves/p256"; // Needed for P256_ORDER

export const CURVE_NAME = "P-256"; // Still relevant for context, matches noble p256
export const HASH_ALGORITHM_NAME = "SHA-256"; // For Web Crypto hashData
export const HMAC_ALGORITHM = {
  name: "HMAC",
  hash: { name: "SHA-256" },
} as const; // For Web Crypto HKDF/HMACKey import
export const AES_ALGORITHM = { name: "AES-GCM", length: 256 } as const; // For Web Crypto AES
export const INFO_RATCHET = new TextEncoder().encode("TripleRatchetInfo");
export const MAX_SKIP = 100; // Maximum number of message keys to skip
export const P256_ORDER = p256.CURVE.n; // Order of the P-256 curve for modular arithmetic
