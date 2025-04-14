// === File: src/utils/buffer.ts ===

import {
  bytesToHex as nobleBytesToHex,
  hexToBytes as nobleHexToBytes,
} from "@noble/hashes/utils";

/**
 * Concatenates multiple ArrayBuffers or Uint8Arrays.
 * @param buffers ArrayBuffers or Uint8Arrays to concatenate.
 * @returns A new Uint8Array containing the concatenated data.
 */
export function concatBuffers(
  ...buffers: (ArrayBuffer | Uint8Array)[]
): Uint8Array {
  const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;

  for (const buffer of buffers) {
    result.set(new Uint8Array(buffer), offset);
    offset += buffer.byteLength;
  }

  return result;
}

/**
 * Compares two ArrayBuffers or Uint8Arrays for equality.
 * Uses constant time comparison if possible.
 * @param a The first buffer.
 * @param b The second buffer.
 * @returns True if the buffers are identical, false otherwise.
 */
export function equalBuffers(
  a: ArrayBuffer | Uint8Array,
  b: ArrayBuffer | Uint8Array
): boolean {
  const viewA = new Uint8Array(a);
  const viewB = new Uint8Array(b);

  if (viewA.length !== viewB.length) {
    return false;
  }

  // Constant time comparison
  let diff = 0;
  for (let i = 0; i < viewA.length; i++) {
    diff |= viewA[i] ^ viewB[i];
  }
  return diff === 0;
}

// Use noble-hashes utilities for hex conversion and re-export
export const bytesToHex = nobleBytesToHex;
export const hexToBytes = nobleHexToBytes;

/**
 * Converts a UTF-8 string to an Uint8Array.
 * @param str The string to encode.
 * @returns The Uint8Array representation.
 */
export function stringToBytes(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

/**
 * Converts an ArrayBuffer or Uint8Array to a UTF-8 string.
 * @param buffer The buffer to decode.
 * @returns The decoded string.
 */
export function bytesToString(buffer: ArrayBuffer | Uint8Array): string {
  return new TextDecoder().decode(buffer);
}
