// === File: src/crypto/crypto-utils.ts ===

import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
// import { hmac } from '@noble/hashes/hmac'; // Only needed for manual HKDF
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { getCrypto } from "../utils/environment"; // Use relative path
import { concatBuffers, equalBuffers } from "../utils/buffer"; // Use relative path - Added equalBuffers import
import {
  AES_ALGORITHM,
  HMAC_ALGORITHM,
  HASH_ALGORITHM_NAME,
  INFO_RATCHET, // Needed for HKDF
} from "../constants"; // Use relative path
import type {
  // Use 'type' import for interfaces/types
  ECKeyPair,
  SigningKeyPair,
  ECDHPublicKey,
  ECDHPrivateKey,
  ECDSAPublicKey,
  ECDSAPrivateKey,
  SerializedECPublicKey, // This type uses hex string now
  HMACKey,
  AESKey,
} from "../types"; // Use relative path

/**
 * Generates a new ECDH key pair (P-256) using noble-curves.
 * @returns An ECKeyPair with keys as Uint8Array.
 */
export function generateECDHKeyPair(): ECKeyPair {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(privateKey, false); // false = uncompressed format
  return {
    privateKey: privateKey, // 32 bytes scalar
    publicKey: publicKey, // 65 bytes (0x04 + x + y)
  };
}

/**
 * Generates a new ECDSA signing key pair (P-256) using noble-curves.
 * @returns A SigningKeyPair with keys as Uint8Array.
 */
export function generateSigningKeyPair(): SigningKeyPair {
  const privateKey = p256.utils.randomPrivateKey();
  const publicKey = p256.getPublicKey(privateKey, false); // Use uncompressed for consistency
  return {
    privateKey: privateKey,
    publicKey: publicKey,
  };
}

/**
 * Computes Diffie-Hellman shared secret using noble-curves (P-256).
 * @param privateKey Our ECDH private key bytes.
 * @param publicKey Their ECDH public key bytes (uncompressed or compressed).
 * @returns The shared secret as a Uint8Array (32 bytes, x-coordinate).
 */
export function computeDH(
  privateKey: ECDHPrivateKey,
  publicKey: ECDHPublicKey
): Uint8Array {
  // noble automatically handles compressed/uncompressed public keys
  const sharedPoint = p256.getSharedSecret(privateKey, publicKey);
  // The shared secret is the x-coordinate of the shared point.
  // Noble's getSharedSecret returns the 32-byte x-coordinate directly.
  return sharedPoint;
}

/**
 * Derives keys using HKDF (HMAC-SHA256) via Web Crypto.
 * @param input The input key material (IKM) (ArrayBuffer or Uint8Array).
 * @param salt Optional salt (recommended) (ArrayBuffer or Uint8Array). Defaults to zero bytes.
 * @param info Optional context/application-specific info (ArrayBuffer or Uint8Array). Defaults to empty.
 * @param keyCount The number of output keys to derive.
 * @param keyLengthBytes The length of each derived key in bytes (default: 32).
 * @returns A Promise resolving to an array of derived keys (ArrayBuffer).
 */
export async function hkdfDerive(
  input: ArrayBuffer | Uint8Array,
  salt: ArrayBuffer | Uint8Array | null,
  info: ArrayBuffer | Uint8Array | null,
  keyCount: number,
  keyLengthBytes: number = 32
): Promise<ArrayBuffer[]> {
  const crypto = getCrypto();
  const saltBytes = salt ? new Uint8Array(salt) : new Uint8Array(32); // Default salt: 32 zeros
  const infoBytes = info ? new Uint8Array(info) : new Uint8Array(0); // Default info: empty
  const inputBytes = new Uint8Array(input);

  // 1. Import IKM as a temporary key for HKDF
  const ikmKey = await crypto.subtle.importKey(
    "raw",
    inputBytes,
    { name: "HKDF" },
    false,
    ["deriveKey"]
  );

  // 2. Derive the keys
  const derivedKeyPromises = [];
  for (let i = 0; i < keyCount; i++) {
    // Append counter to info for unique keys per derivation
    const currentInfo = concatBuffers(infoBytes, new Uint8Array([i]));
    derivedKeyPromises.push(
      crypto.subtle
        .deriveKey(
          {
            name: "HKDF",
            salt: saltBytes,
            info: currentInfo, // Use unique info for each key
            hash: HASH_ALGORITHM_NAME,
          },
          ikmKey,
          // Specify the algorithm for the *derived* key (HMAC in this case, but could be AES)
          // For raw bytes export, using HMAC or AES key type here doesn't strictly matter
          // as long as the length is correct and we export it raw.
          // Using HMAC as a common case for derived symmetric keys.
          {
            name: "HMAC",
            hash: HASH_ALGORITHM_NAME,
            length: keyLengthBytes * 8,
          },
          true, // Allow export
          ["sign", "verify"] // Permissions for the derived key (if kept as CryptoKey)
        )
        .then((key) => crypto.subtle.exportKey("raw", key)) // Export as raw bytes
    );
  }
  return Promise.all(derivedKeyPromises);
}

/**
 * Imports a raw key as an HMAC key (SHA-256) using Web Crypto.
 * @param keyData The raw key material (ArrayBuffer or Uint8Array).
 * @returns A Promise resolving to the HMACKey (CryptoKey).
 */
export async function importHmacKey(
  keyData: ArrayBuffer | Uint8Array
): Promise<HMACKey> {
  const crypto = getCrypto();
  return crypto.subtle.importKey("raw", keyData, HMAC_ALGORITHM, false, [
    "sign",
    "verify",
  ]);
}

/**
 * Imports a raw key as an AES-GCM key (256-bit) using Web Crypto.
 * @param keyData The raw key material (ArrayBuffer or Uint8Array, must be 32 bytes).
 * @returns A Promise resolving to the AESKey (CryptoKey).
 */
export async function importAesKey(
  keyData: ArrayBuffer | Uint8Array
): Promise<AESKey> {
  const keyBytes = new Uint8Array(keyData);
  if (keyBytes.length !== 32) {
    throw new Error(
      `AES key data must be 32 bytes, received ${keyBytes.length}`
    );
  }
  const crypto = getCrypto();
  return crypto.subtle.importKey("raw", keyBytes, AES_ALGORITHM, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Signs data with an ECDSA private key (P-256 SHA-256) using noble-curves.
 * @param privateKey The ECDSAPrivateKey bytes to sign with.
 * @param data The Uint8Array data to sign.
 * @returns A Promise resolving to the signature as a Uint8Array (compact R/S format).
 */
export async function signData(
  privateKey: ECDSAPrivateKey,
  data: Uint8Array // Data to be signed (will be hashed)
): Promise<Uint8Array> {
  const messageHash = sha256(data); // Hash the data first
  // Use p256.sign, which returns a Signature object
  const signature = await p256.sign(messageHash, privateKey);
  // Convert to compact format (64 bytes R || S)
  return signature.toCompactRawBytes();
}

/**
 * Verifies an ECDSA signature (P-256 SHA-256) using noble-curves.
 * @param publicKey The ECDSAPublicKey bytes to verify with.
 * @param signature The signature Uint8Array (compact R/S format expected).
 * @param data The original data Uint8Array (will be hashed internally).
 * @returns A Promise resolving to true if the signature is valid, false otherwise.
 */
export async function verifySignature(
  publicKey: ECDSAPublicKey,
  signature: Uint8Array, // Expecting compact R/S format
  data: Uint8Array // The original data that was signed
): Promise<boolean> {
  const messageHash = sha256(data); // Hash the data first
  try {
    // Use p256.verify. It expects the signature in compact format or as a Signature object.
    // Passing the compact bytes directly is usually supported.
    return p256.verify(signature, messageHash, publicKey);
  } catch (error) {
    console.error("Signature verification failed:", error);
    return false;
  }
}

/**
 * Serializes an EC public key (Uint8Array) to a hex string.
 * @param publicKey The public key bytes.
 * @returns The hex string representation (SerializedECPublicKey).
 */
export function serializePublicKey(
  publicKey: ECDHPublicKey | ECDSAPublicKey
): SerializedECPublicKey {
  return bytesToHex(publicKey);
}

/**
 * Deserializes an EC public key from a hex string.
 * @param serialized The hex string representation.
 * @returns The public key as Uint8Array.
 */
export function deserializePublicKey(
  serialized: SerializedECPublicKey
): Uint8Array {
  // Add validation if needed (e.g., check length, format)
  return hexToBytes(serialized);
}

/**
 * Computes a SHA-256 hash of the input data using Web Crypto.
 * @param data The ArrayBuffer or Uint8Array data to hash.
 * @returns A Promise resolving to the hash digest as an ArrayBuffer (32 bytes).
 */
export async function hashData(
  data: ArrayBuffer | Uint8Array
): Promise<ArrayBuffer> {
  const crypto = getCrypto();
  return crypto.subtle.digest(HASH_ALGORITHM_NAME, data);
}

/**
 * Encrypts data using AES-GCM (256-bit) via Web Crypto.
 * @param key The AESKey (CryptoKey) to use for encryption.
 * @param plaintext The ArrayBuffer or Uint8Array data to encrypt.
 * @param iv The initialization vector (ArrayBuffer or Uint8Array, typically 12 bytes).
 * @param additionalData Optional additional authenticated data (AAD) (ArrayBuffer or Uint8Array).
 * @returns A Promise resolving to the ciphertext as an ArrayBuffer.
 */
export async function encryptAES(
  key: AESKey,
  plaintext: ArrayBuffer | Uint8Array,
  iv: ArrayBuffer | Uint8Array,
  additionalData?: ArrayBuffer | Uint8Array
): Promise<ArrayBuffer> {
  const crypto = getCrypto();
  const params: AesGcmParams = { name: AES_ALGORITHM.name, iv: iv };
  if (additionalData) {
    params.additionalData = additionalData;
  }
  return crypto.subtle.encrypt(params, key, plaintext);
}

/**
 * Decrypts data using AES-GCM (256-bit) via Web Crypto.
 * @param key The AESKey (CryptoKey) to use for decryption.
 * @param ciphertext The ArrayBuffer or Uint8Array data to decrypt.
 * @param iv The initialization vector (ArrayBuffer or Uint8Array) used during encryption.
 * @param additionalData Optional additional authenticated data (AAD) used during encryption.
 * @returns A Promise resolving to the original plaintext as an ArrayBuffer.
 */
export async function decryptAES(
  key: AESKey,
  ciphertext: ArrayBuffer | Uint8Array,
  iv: ArrayBuffer | Uint8Array,
  additionalData?: ArrayBuffer | Uint8Array
): Promise<ArrayBuffer> {
  const crypto = getCrypto();
  const params: AesGcmParams = { name: AES_ALGORITHM.name, iv: iv };
  if (additionalData) {
    params.additionalData = additionalData;
  }
  try {
    return await crypto.subtle.decrypt(params, key, ciphertext);
  } catch (e) {
    console.error("AES decryption failed:", e);
    throw new Error(
      `Decryption failed. Data may be corrupt or key/IV incorrect. ${e}`
    );
  }
}

/**
 * Exports a Web Crypto CryptoKey to its raw representation (ArrayBuffer).
 * @param key The CryptoKey to export (must be exportable and support 'raw' format).
 * @returns A Promise resolving to the raw key material as an ArrayBuffer.
 */
export async function exportRawKey(key: CryptoKey): Promise<ArrayBuffer> {
  const crypto = getCrypto();
  try {
    return await crypto.subtle.exportKey("raw", key);
  } catch (e) {
    console.error("Failed to export raw key:", e);
    throw new Error(`Could not export key in raw format: ${e}`);
  }
}

/**
 * Compares two public keys (Uint8Array) for equality using constant time buffer comparison.
 * @param keyA The first public key bytes.
 * @param keyB The second public key bytes.
 * @returns True if the keys are equal, false otherwise.
 */
export function equalPublicKeys(
  keyA: ECDHPublicKey | ECDSAPublicKey,
  keyB: ECDHPublicKey | ECDSAPublicKey
): boolean {
  // Use the imported equalBuffers function
  return equalBuffers(keyA, keyB);
}
