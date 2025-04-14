// === File: src/utils/environment.ts ===

/**
 * Environment detection utilities
 */
export const isBrowser =
  typeof window !== "undefined" && typeof window.crypto !== "undefined";

/**
 * Gets the crypto implementation from the environment (for Web Crypto parts).
 * @throws Error if Web Crypto API is not available.
 * @returns The Crypto object.
 */
export function getCrypto(): Crypto {
  if (isBrowser) {
    return window.crypto;
  }
  throw new Error("Web Crypto API is not available in this environment");
}
